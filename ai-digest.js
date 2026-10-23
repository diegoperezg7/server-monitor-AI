// AI security digest: turns the events the monitor already collects into a short,
// prioritised summary. The LLM only summarises a closed list of events; it never
// triggers actions. Without Ollama, or when its answer does not validate, the
// deterministic digest below is used instead.

const WINDOW_MS = 24 * 60 * 60 * 1000;
const MAX_EVENTS = 60;
const MAX_PRIORITIES = 3;

const SYSTEM_SEVERITY = {
  server_down: 3, container_down: 3, container_restart: 3,
  disk_high: 2, cpu_high: 2, ram_high: 2, under_attack: 2,
  server_up: 0, container_up: 0,
};

function stripHtml(text) {
  return String(text || '').replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
}

function escapeHtml(text) {
  return String(text || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * Build the closed list of events the digest may talk about.
 * crowdsecAlerts: CrowdSec LAPI alerts (already filtered to actionable ones).
 * decisions: active CrowdSec decisions.
 * history: the monitor's own alert history ({ type, title, message, time }).
 */
function collectEvents({ crowdsecAlerts = [], decisions = [], history = [], now = Date.now() } = {}) {
  const since = now - WINDOW_MS;
  const events = [];

  for (const a of crowdsecAlerts) {
    const time = a.created_at ? new Date(a.created_at).getTime() : NaN;
    if (!a.id || !(time >= since)) continue;
    const count = Number(a.events_count || 0);
    const ip = a.source?.ip || a.source?.value || 'unknown';
    events.push({
      id: `cs-${a.id}`, kind: 'crowdsec_alert', time: new Date(time).toISOString(), ip,
      severity: count >= 10 ? 2 : 1, count,
      text: `CrowdSec ${a.scenario || 'escenario desconocido'} desde ${ip}, ${count} eventos`,
    });
  }

  for (const d of decisions) {
    if (!d.value) continue;
    // Bans are CrowdSec's own response, already applied: context rather than a priority.
    events.push({
      id: `ban-${d.id ?? d.value}`, kind: 'ban', time: null, ip: d.value, severity: 1, count: 0,
      text: `Bloqueo activo (${d.type || 'ban'}) de ${d.value}, quedan ${d.duration || '?'} (${d.scenario || 'escenario desconocido'})`,
    });
  }

  for (const h of history) {
    if (!(h.time >= since) || !(h.type in SYSTEM_SEVERITY)) continue;
    events.push({
      id: `sys-${h.time}`, kind: 'system', time: new Date(h.time).toISOString(),
      severity: SYSTEM_SEVERITY[h.type], count: 0,
      text: `${h.title}: ${stripHtml(h.message)}`,
    });
  }

  events.sort((a, b) => b.severity - a.severity || b.count - a.count || String(b.time).localeCompare(String(a.time)));
  return events.slice(0, MAX_EVENTS);
}

const DIGEST_SCHEMA = {
  type: 'object',
  properties: {
    summary: { type: 'string' },
    priorities: {
      type: 'array',
      maxItems: MAX_PRIORITIES,
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          reason: { type: 'string' },
          event_ids: { type: 'array', items: { type: 'string' } },
        },
        required: ['title', 'reason', 'event_ids'],
      },
    },
  },
  required: ['summary', 'priorities'],
};

function buildMessages(events) {
  const system = [
    'Eres un asistente que resume la seguridad de un unico servidor domestico.',
    'Reglas:',
    '- Usa SOLO los eventos de la lista. No inventes eventos, IPs, horas ni cifras.',
    '- Cada prioridad debe citar ids que aparezcan literalmente en la lista.',
    '- Ordena por lo que conviene mirar primero: servicios caidos, recursos al limite y ataques activos antes que ruido de escaneo.',
    '- Si los eventos son rutinarios, dilo claramente.',
    '- No propongas ejecutar acciones automaticas; como mucho, que revisar.',
    '- Responde en espanol, solo JSON con { "summary": string, "priorities": [{ "title", "reason", "event_ids" }] }, maximo 3 prioridades y un resumen de 2 o 3 frases.',
  ].join('\n');
  const list = events.map(e => JSON.stringify({ id: e.id, time: e.time, kind: e.kind, text: e.text })).join('\n');
  return [
    { role: 'system', content: system },
    { role: 'user', content: `Eventos de las ultimas 24 horas (${events.length}):\n${list}` },
  ];
}

/**
 * Validate the model output against the closed event list. Unknown ids are dropped;
 * a priority with no known id is discarded. Returns null when the output is unusable.
 */
function validateDigest(raw, events) {
  let data = raw;
  if (typeof raw === 'string') {
    const text = raw.trim().replace(/^```(?:json)?\s*/i, '').replace(/```$/, '').trim();
    try { data = JSON.parse(text); } catch { return null; }
  }
  if (!data || typeof data !== 'object') return null;

  const summary = typeof data.summary === 'string' ? data.summary.trim().slice(0, 600) : '';
  if (!summary) return null;

  const known = new Set(events.map(e => e.id));
  const proposed = Array.isArray(data.priorities) ? data.priorities : [];
  const priorities = [];
  let dropped = 0;
  for (const p of proposed) {
    if (!p || typeof p !== 'object') { dropped++; continue; }
    const ids = [...new Set(Array.isArray(p.event_ids) ? p.event_ids.map(String) : [])];
    const valid = ids.filter(id => known.has(id));
    dropped += ids.length - valid.length;
    const title = typeof p.title === 'string' ? p.title.trim().slice(0, 120) : '';
    if (!title || valid.length === 0) continue;
    priorities.push({ title, reason: typeof p.reason === 'string' ? p.reason.trim().slice(0, 300) : '', event_ids: valid });
    if (priorities.length === MAX_PRIORITIES) break;
  }

  // Priorities were proposed but none survived: the answer is not grounded in the input.
  if (proposed.length > 0 && priorities.length === 0) return null;
  return { summary, priorities, dropped_ids: dropped };
}

function deterministicDigest(events) {
  const alerts = events.filter(e => e.kind === 'crowdsec_alert');
  const bans = events.filter(e => e.kind === 'ban');
  const system = events.filter(e => e.kind === 'system' && e.severity > 0);
  const ips = new Set(alerts.map(e => e.ip));
  const summary = `${events.length} eventos en 24 h: ${alerts.length} alertas de CrowdSec desde ${ips.size} IPs, ` +
    `${bans.length} bloqueos activos y ${system.length} avisos del sistema.`;
  const reasons = {
    system: 'Aviso del propio servidor: afecta a la disponibilidad.',
    crowdsec_alert: 'Alerta de CrowdSec con mas eventos del periodo.',
    ban: 'Bloqueo ya aplicado por CrowdSec; revisar solo si se repite.',
  };
  const priorities = events
    .filter(e => e.severity > 0)
    .slice(0, MAX_PRIORITIES)
    .map(e => ({ title: e.text, reason: reasons[e.kind], event_ids: [e.id] }));
  return { summary, priorities, dropped_ids: 0 };
}

async function callOllama(messages, { url, model, timeoutMs, fetchImpl }) {
  const res = await fetchImpl(url.replace(/\/+$/, '') + '/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, messages, stream: false, format: DIGEST_SCHEMA, options: { temperature: 0 } }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`Ollama HTTP ${res.status}`);
  const body = await res.json();
  return body?.message?.content ?? '';
}

/**
 * Produce the digest. options: { enabled, url, model, timeoutMs, fetchImpl, now }.
 */
async function generateDigest(events, options = {}) {
  const { enabled = false, url = '', model = '', timeoutMs = 20000, fetchImpl = globalThis.fetch, now = Date.now() } = options;
  const base = { generated_at: new Date(now).toISOString(), window_hours: WINDOW_MS / 3600000, event_count: events.length };
  const withEvents = d => ({
    ...d,
    priorities: d.priorities.map(p => ({ ...p, events: p.event_ids.map(id => events.find(e => e.id === id)) })),
  });

  if (events.length === 0) {
    return { ...base, source: 'none', summary: 'Sin eventos en las ultimas 24 horas.', priorities: [], dropped_ids: 0 };
  }
  if (!enabled || !url || !model) {
    return { ...base, source: 'deterministic', fallback_reason: 'disabled', ...withEvents(deterministicDigest(events)) };
  }
  try {
    const content = await callOllama(buildMessages(events), { url, model, timeoutMs, fetchImpl });
    const valid = validateDigest(content, events);
    if (!valid) return { ...base, source: 'deterministic', fallback_reason: 'invalid_output', ...withEvents(deterministicDigest(events)) };
    return { ...base, source: 'llm', model, ...withEvents(valid) };
  } catch (e) {
    const reason = e?.name === 'TimeoutError' ? 'timeout' : 'unreachable';
    return { ...base, source: 'deterministic', fallback_reason: reason, ...withEvents(deterministicDigest(events)) };
  }
}

function formatTelegram(digest, dashboardUrl = '') {
  const label = digest.source === 'llm' ? `IA (${escapeHtml(digest.model)})` : 'determinista';
  let text = `\u{1F9E0} <b>Resumen de seguridad</b> <i>(${label})</i>\n<i>Ultimas ${digest.window_hours} horas, ${digest.event_count} eventos</i>\n\n`;
  text += `${escapeHtml(digest.summary)}\n`;
  digest.priorities.forEach((p, i) => {
    text += `\n<b>${i + 1}. ${escapeHtml(p.title)}</b>\n`;
    if (p.reason) text += `${escapeHtml(p.reason)}\n`;
    text += `<code>${p.event_ids.map(escapeHtml).join(', ')}</code>\n`;
  });
  if (dashboardUrl) text += `\n\u{1F4CA} <a href="${escapeHtml(dashboardUrl)}">Dashboard</a>\n`;
  return text;
}

module.exports = { collectEvents, buildMessages, validateDigest, deterministicDigest, generateDigest, formatTelegram, DIGEST_SCHEMA };
