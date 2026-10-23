const test = require('node:test');
const assert = require('node:assert/strict');

const { collectEvents, validateDigest, generateDigest, formatTelegram } = require('../ai-digest');

const NOW = Date.parse('2026-10-23T12:00:00Z');
const hoursAgo = h => NOW - h * 3600000;

function sampleEvents() {
  return collect().events;
}

function collect() {
  return collectEvents({
    now: NOW,
    crowdsecAlerts: [
      { id: 101, scenario: 'crowdsecurity/ssh-bf', created_at: new Date(hoursAgo(2)).toISOString(), events_count: 14, source: { ip: '203.0.113.10' } },
      { id: 102, scenario: 'crowdsecurity/http-probing', created_at: new Date(hoursAgo(5)).toISOString(), events_count: 3, source: { ip: '198.51.100.7' } },
      { id: 99, scenario: 'crowdsecurity/ssh-bf', created_at: new Date(hoursAgo(30)).toISOString(), events_count: 8, source: { ip: '192.0.2.4' } },
    ],
    decisions: [{ id: 7, value: '203.0.113.10', type: 'ban', duration: '3h40m', scenario: 'crowdsecurity/ssh-bf' }],
    history: [
      { type: 'container_down', title: 'Contenedor Caido', message: 'El contenedor <b>postgres</b> ha dejado de funcionar.', time: hoursAgo(1) },
      { type: 'security_digest', title: 'Resumen de Seguridad', message: 'not an event', time: hoursAgo(1) },
    ],
  });
}

function fakeOllama(content, { status = 200, delayMs = 0 } = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body) });
    if (delayMs) {
      await new Promise((resolve, reject) => {
        const t = setTimeout(resolve, delayMs);
        init.signal.addEventListener('abort', () => { clearTimeout(t); reject(init.signal.reason); });
      });
    }
    return { ok: status === 200, status, json: async () => ({ message: { content } }) };
  };
  return { fetchImpl, calls };
}

const enabled = fetchImpl => ({ enabled: true, url: 'http://ollama.test:11434', model: 'qwen2.5:7b', timeoutMs: 200, fetchImpl, now: NOW });

test('collectEvents keeps the last 24 hours and only known system types', () => {
  const ids = sampleEvents().map(e => e.id);
  assert.deepEqual(ids.sort(), ['ban-7', 'cs-101', 'cs-102', `sys-${hoursAgo(1)}`].sort());
});

test('collectEvents reports uncapped totals', () => {
  const { totals } = collect();
  assert.deepEqual(totals, { events: 4, crowdsec_alerts: 2, ips: 2, bans: 1, system: 1 });
});

test('the deterministic summary uses the totals, not the capped list', async () => {
  const events = sampleEvents();
  const totals = { events: 80, crowdsec_alerts: 40, ips: 30, bans: 34, system: 6 };
  const digest = await generateDigest(events, { totals, now: NOW });
  assert.match(digest.summary, /^80 eventos en 24 h: 40 alertas de CrowdSec desde 30 IPs, 34 bloqueos activos ahora y 6 avisos/);
});

test('collectEvents orders by severity first', () => {
  const events = sampleEvents();
  assert.equal(events[0].id, `sys-${hoursAgo(1)}`);
  assert.equal(events[0].text, 'Contenedor Caido: El contenedor postgres ha dejado de funcionar.');
  assert.equal(events[1].id, 'cs-101');
});

test('validateDigest drops ids that are not in the input', () => {
  const events = sampleEvents();
  const out = validateDigest(JSON.stringify({
    summary: 'Postgres caido y fuerza bruta SSH.',
    priorities: [
      { title: 'Postgres caido', reason: 'Servicio caido', event_ids: [`sys-${hoursAgo(1)}`, 'sys-404'] },
      { title: 'Inventado', reason: 'No existe', event_ids: ['cs-999'] },
    ],
  }), events);
  assert.equal(out.priorities.length, 1);
  assert.deepEqual(out.priorities[0].event_ids, [`sys-${hoursAgo(1)}`]);
  assert.equal(out.dropped_ids, 2);
});

test('validateDigest rejects output whose priorities are all ungrounded', () => {
  const out = validateDigest({ summary: 'Todo inventado', priorities: [{ title: 'x', reason: 'y', event_ids: ['cs-1'] }] }, sampleEvents());
  assert.equal(out, null);
});

test('validateDigest rejects malformed JSON and empty summaries', () => {
  const events = sampleEvents();
  assert.equal(validateDigest('not json', events), null);
  assert.equal(validateDigest('{"summary": "", "priorities": []}', events), null);
});

test('validateDigest accepts fenced JSON and caps priorities at three', () => {
  const events = sampleEvents();
  const ids = events.map(e => e.id);
  const raw = '```json\n' + JSON.stringify({
    summary: 'Resumen.',
    priorities: ids.map(id => ({ title: id, reason: 'r', event_ids: [id] })),
  }) + '\n```';
  assert.equal(validateDigest(raw, events).priorities.length, 3);
});

test('generateDigest uses the model output when it validates', async () => {
  const events = sampleEvents();
  const { fetchImpl, calls } = fakeOllama(JSON.stringify({
    summary: 'Postgres esta caido desde hace una hora.',
    priorities: [{ title: 'Postgres caido', reason: 'Base de datos sin servicio', event_ids: [`sys-${hoursAgo(1)}`] }],
  }));
  const digest = await generateDigest(events, enabled(fetchImpl));
  assert.equal(digest.source, 'llm');
  assert.equal(digest.priorities[0].events[0].kind, 'system');
  assert.equal(calls[0].url, 'http://ollama.test:11434/api/chat');
  assert.equal(calls[0].body.stream, false);
  assert.match(calls[0].body.messages[1].content, /cs-101/);
  assert.match(calls[0].body.messages[1].content, /1 bloqueos activos/);
});

test('generateDigest falls back when the model invents events', async () => {
  const { fetchImpl } = fakeOllama(JSON.stringify({ summary: 'x', priorities: [{ title: 'y', reason: 'z', event_ids: ['cs-12345'] }] }));
  const digest = await generateDigest(sampleEvents(), enabled(fetchImpl));
  assert.equal(digest.source, 'deterministic');
  assert.equal(digest.fallback_reason, 'invalid_output');
  assert.ok(digest.priorities.length > 0);
});

test('generateDigest falls back on timeout', async () => {
  const { fetchImpl } = fakeOllama('{}', { delayMs: 1000 });
  const digest = await generateDigest(sampleEvents(), enabled(fetchImpl));
  assert.equal(digest.source, 'deterministic');
  assert.equal(digest.fallback_reason, 'timeout');
});

test('generateDigest falls back when Ollama is unreachable or errors', async () => {
  const down = async () => { throw new TypeError('fetch failed'); };
  assert.equal((await generateDigest(sampleEvents(), enabled(down))).fallback_reason, 'unreachable');
  const { fetchImpl } = fakeOllama('{}', { status: 500 });
  assert.equal((await generateDigest(sampleEvents(), enabled(fetchImpl))).fallback_reason, 'unreachable');
});

test('generateDigest does not call the model when disabled or without events', async () => {
  const { fetchImpl, calls } = fakeOllama('{}');
  const disabled = await generateDigest(sampleEvents(), { ...enabled(fetchImpl), enabled: false });
  assert.equal(disabled.source, 'deterministic');
  assert.equal(disabled.fallback_reason, 'disabled');
  const empty = await generateDigest([], enabled(fetchImpl));
  assert.equal(empty.source, 'none');
  assert.equal(calls.length, 0);
});

test('formatTelegram escapes model text', async () => {
  const events = sampleEvents();
  const { fetchImpl } = fakeOllama(JSON.stringify({
    summary: '<script>alert(1)</script>',
    priorities: [{ title: 'a & b', reason: 'r', event_ids: ['cs-101'] }],
  }));
  const text = formatTelegram(await generateDigest(events, enabled(fetchImpl)));
  assert.ok(!text.includes('<script>'));
  assert.ok(text.includes('a &amp; b'));
});
