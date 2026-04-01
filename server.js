const express = require('express');
const fs = require('fs/promises');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const net = require('net');
const path = require('path');

const app = express();
const PORT = 3000;
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || '';

const NETDATA = process.env.NETDATA_URL || 'http://127.0.0.1:19999';
const CROWDSEC = process.env.CROWDSEC_URL || 'http://127.0.0.1:8081';
const CS_MACHINE_ID = process.env.CROWDSEC_MACHINE_ID || 'localhost';
const CS_PASSWORD = process.env.CROWDSEC_PASSWORD || '';
const CS_BOUNCER_KEY = process.env.CROWDSEC_BOUNCER_KEY || '';
const NET_IFACE = process.env.NET_INTERFACE || 'en1';
const DASHBOARD_URL = process.env.DASHBOARD_URL || '';
const DOCKER_SOCKET = '/var/run/docker.sock';
const DOCKER_HOST = process.env.DOCKER_HOST || null; // e.g. http://docker-proxy:2375
const RESTORE_STATE_FILE = process.env.RESTORE_STATE_FILE || path.join(__dirname, 'data', 'active-services-state.json');
const AUTO_RESTORE_ON_BOOT = String(process.env.AUTO_RESTORE_ON_BOOT || 'true').toLowerCase() !== 'false';
const RESTORE_STARTUP_DELAY_MS = Number(process.env.RESTORE_STARTUP_DELAY_MS || 15000);
const RESTORE_SYNC_INTERVAL_MS = Number(process.env.RESTORE_SYNC_INTERVAL_MS || 15000);
const RESTORE_RETRY_COUNT = Number(process.env.RESTORE_RETRY_COUNT || 5);
const RESTORE_RETRY_DELAY_MS = Number(process.env.RESTORE_RETRY_DELAY_MS || 5000);

// Telegram config
const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TG_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '';

// Healthchecks.io config
const HC_PING_URL = process.env.HEALTHCHECK_PING_URL || '';

// --- CrowdSec JWT cache ---
let csToken = null;
let csTokenExpiry = 0;

async function getCrowdSecToken() {
  const now = Date.now();
  if (csToken && now < csTokenExpiry - 60000) return csToken;

  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ machine_id: CS_MACHINE_ID, password: CS_PASSWORD });
    const url = new URL(CROWDSEC + '/v1/watchers/login');
    const req = http.request({
      hostname: url.hostname, port: url.port, path: url.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), 'User-Agent': 'server-monitor/1.0' },
      timeout: 5000,
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const j = JSON.parse(data);
          if (j.token) {
            csToken = j.token;
            csTokenExpiry = new Date(j.expire).getTime();
            resolve(csToken);
          } else {
            console.error('CrowdSec login failed:', data);
            resolve(null);
          }
        } catch (e) {
          console.error('CrowdSec login parse error:', data);
          reject(e);
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.end(body);
  });
}

// --- HTTP helpers ---
function fetchJSON(urlStr, headers = {}, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const req = http.request({
      hostname: url.hostname, port: url.port,
      path: url.pathname + url.search,
      headers: { 'User-Agent': 'server-monitor/1.0', ...headers }, timeout,
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve(data); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

function requestDocker(apiPath, options = {}) {
  return new Promise((resolve, reject) => {
    const method = options.method || 'GET';
    const timeout = options.timeout || 5000;
    const headers = { ...(options.headers || {}) };
    const okStatuses = Array.isArray(options.okStatuses) && options.okStatuses.length > 0
      ? new Set(options.okStatuses)
      : null;
    const requestBody =
      options.body == null
        ? null
        : typeof options.body === 'string'
          ? options.body
          : JSON.stringify(options.body);

    if (requestBody != null) {
      if (!headers['Content-Type']) headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(requestBody);
    }

    let opts;
    if (DOCKER_HOST) {
      const base = new URL(DOCKER_HOST);
      opts = { hostname: base.hostname, port: base.port || 80, path: apiPath, method, headers, timeout };
    } else {
      opts = { socketPath: DOCKER_SOCKET, path: apiPath, method, headers, timeout };
    }
    const req = http.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        const statusCode = res.statusCode || 0;
        const isOk = okStatuses ? okStatuses.has(statusCode) : (statusCode >= 200 && statusCode < 300);

        if (!isOk) {
          const err = new Error(`Docker API ${statusCode}${data ? `: ${String(data).slice(0, 200)}` : ''}`);
          err.statusCode = statusCode;
          err.body = data;
          return reject(err);
        }

        let parsed = data;
        try { resolve(JSON.parse(data)); }
        catch { resolve({ statusCode, data: parsed }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if (requestBody != null) req.end(requestBody);
    else req.end();
  });
}

async function fetchDocker(apiPath, options = {}) {
  const response = await requestDocker(apiPath, options);
  if (response && typeof response === 'object' && Object.prototype.hasOwnProperty.call(response, 'statusCode') && Object.prototype.hasOwnProperty.call(response, 'data')) {
    return response.data;
  }
  return response;
}

// =========================================================
// HEALTHCHECKS.IO HEARTBEAT
// =========================================================
let lastHeartbeat = 0;
let heartbeatOk = null;

function sendHeartbeat() {
  if (!HC_PING_URL) return;
  const mod = HC_PING_URL.startsWith('https') ? https : http;
  const req = mod.get(HC_PING_URL, { timeout: 10000 }, (res) => {
    heartbeatOk = res.statusCode === 200;
    lastHeartbeat = Date.now();
    res.resume();
  });
  req.on('error', () => { heartbeatOk = false; });
  req.on('timeout', () => { req.destroy(); heartbeatOk = false; });
}

// Heartbeat every 60s
setTimeout(() => {
  sendHeartbeat();
  setInterval(sendHeartbeat, 60000);
}, 2000);

// =========================================================
// IP GEOLOCATION
// =========================================================
const geoCache = new Map();
const GEO_CACHE_TTL = 24 * 60 * 60 * 1000;

function isPrivateIP(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.|::1|fe80:)/.test(ip);
}

function normalizeIP(raw) {
  if (!raw) return '';
  let ip = String(raw).trim();
  if (ip.includes(',')) ip = ip.split(',')[0].trim();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  return ip;
}

function isActionableCrowdSecAlert(alert) {
  const sourceScope = String(alert?.source?.scope || '').toLowerCase();
  const scenario = String(alert?.scenario || '').toLowerCase();
  const events = Number(alert?.events_count || 0);

  if (sourceScope === 'crowdsecurity/community-blocklist') return false;
  if (scenario.startsWith('update : +') && events === 0) return false;
  return true;
}

function geoLookupBatch(ips) {
  return new Promise((resolve) => {
    const publicIps = ips.filter(ip => !isPrivateIP(ip));
    const uncached = publicIps.filter(ip => {
      const c = geoCache.get(ip);
      return !c || (Date.now() - c._time > GEO_CACHE_TTL);
    });

    function buildResult() {
      return ips.map(ip => {
        if (isPrivateIP(ip)) return { ip, country: 'Red Local', countryCode: 'LO', city: '', lat: 0, lon: 0, isp: 'Local', org: 'Local', as: '' };
        const c = geoCache.get(ip);
        return c ? { ip, country: c.country, countryCode: c.countryCode, city: c.city, lat: c.lat, lon: c.lon, isp: c.isp, org: c.org, as: c.as } : { ip, country: 'Desconocido', countryCode: '--', city: '', lat: 0, lon: 0, isp: '', org: '', as: '' };
      });
    }

    if (uncached.length === 0) return resolve(buildResult());

    const batch = uncached.slice(0, 100);
    const body = JSON.stringify(batch);
    const req = http.request({
      hostname: 'ip-api.com',
      path: '/batch?fields=status,country,countryCode,city,lat,lon,isp,org,as,query',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 10000,
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const results = JSON.parse(data);
          if (Array.isArray(results)) {
            results.forEach(r => {
              if (r.status === 'success') {
                geoCache.set(r.query, { country: r.country, countryCode: r.countryCode, city: r.city, lat: r.lat, lon: r.lon, isp: r.isp, org: r.org, as: r.as, _time: Date.now() });
              }
            });
          }
        } catch {}
        resolve(buildResult());
      });
    });
    req.on('error', () => resolve(buildResult()));
    req.on('timeout', () => { req.destroy(); resolve(buildResult()); });
    req.end(body);
  });
}

// =========================================================
// ATTACK HISTORY (in-memory, rolling 7 days)
// =========================================================
const attackHistory = [];
const ATTACK_HISTORY_MAX = 2000;

function recordAttack(entry) {
  attackHistory.unshift({ time: Date.now(), ...entry });
  const cutoff = Date.now() - 7 * 86400000;
  while (attackHistory.length > ATTACK_HISTORY_MAX) attackHistory.pop();
  while (attackHistory.length > 0 && attackHistory[attackHistory.length - 1].time < cutoff) attackHistory.pop();
}

// =========================================================
// TELEGRAM ALERT SYSTEM
// =========================================================

function sendTelegram(text) {
  if (!TG_TOKEN || !TG_CHAT_ID) return Promise.resolve(false);
  return new Promise((resolve) => {
    const body = JSON.stringify({
      chat_id: TG_CHAT_ID,
      text,
      parse_mode: 'HTML',
      disable_web_page_preview: true,
    });
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${TG_TOKEN}/sendMessage`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 10000,
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const j = JSON.parse(data);
          resolve(j.ok === true);
        } catch {
          resolve(false);
        }
      });
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end(body);
  });
}

// Alert state
let netdataConsecutiveFailures = 0;

const alertState = {
  lastSent: {},
  history: [],
  serverDown: false,
  prevContainers: {},
  prevDecisionCount: 0,
  prevAlertIds: new Set(),
  consecutiveHighCpu: 0,
  consecutiveHighRam: 0,
  telegramOk: null,
};

// Security digest buffer
const securityDigest = {
  alerts: [],          // { scenario, source, events, time }
  bans: [],            // { ip, type, scenario, duration, time }
  lastDigestSent: Date.now(),
  underAttackSent: false,
};
const DIGEST_INTERVAL = 12 * 60 * 60 * 1000; // resumen cada 12 horas
const UNDER_ATTACK_THRESHOLD = 15;          // alerta inmediata si +15 eventos en una ventana

const COOLDOWNS = {
  cpu_high: 5 * 60 * 1000,
  ram_high: 5 * 60 * 1000,
  disk_high: 15 * 60 * 1000,
  server_down: 60 * 1000,
  server_up: 0,
  container_down: 2 * 60 * 1000,
  container_up: 0,
  container_restart: 2 * 60 * 1000,
};

function canSendAlert(type) {
  const cooldown = COOLDOWNS[type] || 60000;
  const last = alertState.lastSent[type] || 0;
  return Date.now() - last >= cooldown;
}

async function sendAlert(type, title, message) {
  if (!canSendAlert(type)) return false;
  const emoji = {
    cpu_high: '\u{1F525}', ram_high: '\u{1F4A5}', disk_high: '\u{1F4BE}',
    server_down: '\u{1F6A8}', server_up: '\u{2705}',
    container_down: '\u{1F4E6}', container_up: '\u{2705}', container_restart: '\u{1F504}',
    security_alert: '\u{1F6E1}', security_ban: '\u{26D4}',
  }[type] || '\u{26A0}';

  const dashLink = DASHBOARD_URL ? `\n\n\u{1F4CA} <a href="${DASHBOARD_URL}">Dashboard</a>` : '';
  const text = `${emoji} <b>${title}</b>\n${message}${dashLink}\n\n<i>${new Date().toLocaleString('es-ES')}</i>`;
  const ok = await sendTelegram(text);
  alertState.telegramOk = ok;

  const entry = { type, title, message, time: Date.now(), sent: ok };
  alertState.history.unshift(entry);
  if (alertState.history.length > 50) alertState.history.pop();

  if (ok) alertState.lastSent[type] = Date.now();
  return ok;
}

async function sendSecurityDigest() {
  if (securityDigest.alerts.length === 0 && securityDigest.bans.length === 0) return;

  // Group alerts by scenario
  const scenarioMap = {};
  const alertIps = new Set();
  for (const a of securityDigest.alerts) {
    if (!scenarioMap[a.scenario]) scenarioMap[a.scenario] = { count: 0, events: 0 };
    scenarioMap[a.scenario].count++;
    scenarioMap[a.scenario].events += a.events;
    if (a.source) alertIps.add(a.source);
  }
  const topScenarios = Object.entries(scenarioMap)
    .sort((a, b) => b[1].events - a[1].events)
    .slice(0, 5);

  // Top banned IPs
  const topBans = securityDigest.bans.slice(0, 5);

  let text = `\u{1F6E1} <b>Resumen de Seguridad</b>\n`;
  const hours = Math.round(DIGEST_INTERVAL / 3600000);
  text += `<i>Ultimas ${hours} horas</i>\n\n`;

  if (topScenarios.length > 0) {
    text += `<b>Ataques detectados:</b> ${securityDigest.alerts.length} alertas, ${alertIps.size} IPs unicas\n`;
    for (const [scenario, data] of topScenarios) {
      text += `  \u2022 <code>${scenario}</code> — ${data.count}x (${data.events} eventos)\n`;
    }
    text += '\n';
  }

  if (topBans.length > 0) {
    text += `<b>IPs baneadas:</b> ${securityDigest.bans.length}\n`;
    for (const b of topBans) {
      text += `  \u2022 <code>${b.ip}</code> — ${b.scenario} (${b.duration})\n`;
    }
    text += '\n';
  }

  if (DASHBOARD_URL) text += `\u{1F4CA} <a href="${DASHBOARD_URL}">Dashboard</a>\n`;
  text += `<i>${new Date().toLocaleString('es-ES')}</i>`;

  const ok = await sendTelegram(text);
  alertState.telegramOk = ok;

  const entry = { type: 'security_digest', title: 'Resumen de Seguridad', message: `${securityDigest.alerts.length} alertas, ${securityDigest.bans.length} bans`, time: Date.now(), sent: ok };
  alertState.history.unshift(entry);
  if (alertState.history.length > 50) alertState.history.pop();

  // Clear buffer
  securityDigest.alerts = [];
  securityDigest.bans = [];
  securityDigest.lastDigestSent = Date.now();
  securityDigest.underAttackSent = false;
}

async function sendUnderAttackAlert() {
  if (securityDigest.underAttackSent) return;
  securityDigest.underAttackSent = true;

  const totalEvents = securityDigest.alerts.reduce((sum, a) => sum + a.events, 0);
  const uniqueIps = new Set(securityDigest.alerts.map(a => a.source).filter(Boolean)).size;

  let text = `\u{1F6A8} <b>Ataque en Curso</b>\n\n`;
  text += `Se han acumulado <b>${securityDigest.alerts.length}</b> alertas con <b>${totalEvents}</b> eventos de <b>${uniqueIps}</b> IPs unicas en los ultimos minutos.\n\n`;
  if (DASHBOARD_URL) text += `\u{1F4CA} <a href="${DASHBOARD_URL}">Ver Dashboard</a>\n`;
  text += `<i>${new Date().toLocaleString('es-ES')}</i>`;

  const ok = await sendTelegram(text);
  alertState.telegramOk = ok;

  const entry = { type: 'under_attack', title: 'Ataque en Curso', message: `${securityDigest.alerts.length} alertas, ${totalEvents} eventos`, time: Date.now(), sent: ok };
  alertState.history.unshift(entry);
  if (alertState.history.length > 50) alertState.history.pop();
}

function getContainerLabel(container) {
  const rawName =
    (Array.isArray(container?.Names) && container.Names.find(n => typeof n === 'string' && n.trim())) ||
    container?.Name ||
    '';
  const cleanName = String(rawName).replace(/^\//, '').trim();
  if (cleanName) return cleanName;

  const rawId = String(container?.Id || container?.ID || '').trim();
  if (rawId) return rawId.slice(0, 12);

  return 'desconocido';
}

const restoreRuntime = {
  snapshot: null,
  lastSnapshotSignature: '',
  lastPersistedAt: 0,
  lastPersistError: null,
  lastRestoreResult: null,
  startupRestore: {
    enabled: AUTO_RESTORE_ON_BOOT,
    status: AUTO_RESTORE_ON_BOOT ? 'scheduled' : 'disabled',
    attempts: 0,
    started_at: null,
    finished_at: null,
    error: null,
  },
};

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function getComposeMetadata(labels = {}) {
  const project = labels['com.docker.compose.project'] || null;
  const service = labels['com.docker.compose.service'] || null;
  const workingDir = labels['com.docker.compose.project.working_dir'] || null;
  const configFiles = String(labels['com.docker.compose.project.config_files'] || '')
    .split(',')
    .map(v => v.trim())
    .filter(Boolean);

  return {
    project,
    service,
    working_dir: workingDir,
    config_files: configFiles,
  };
}

function buildRestoreSnapshot(containers) {
  const runningContainers = Array.isArray(containers)
    ? containers.filter(c => c?.State === 'running')
    : [];

  const trackedContainers = runningContainers
    .map(container => {
      const labels = container?.Labels || {};
      const compose = getComposeMetadata(labels);
      return {
        name: getContainerLabel(container),
        id: String(container?.Id || '').slice(0, 12),
        image: container?.Image || '',
        status: container?.Status || 'running',
        project: compose.project,
        service: compose.service,
        working_dir: compose.working_dir,
        config_files: compose.config_files,
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));

  const projectMap = new Map();
  trackedContainers.forEach(container => {
    if (!container.project) return;
    if (!projectMap.has(container.project)) {
      projectMap.set(container.project, {
        project: container.project,
        working_dir: container.working_dir,
        config_files: container.config_files,
        services: [],
      });
    }
    const entry = projectMap.get(container.project);
    if (container.service && !entry.services.includes(container.service)) entry.services.push(container.service);
  });

  const projects = [...projectMap.values()]
    .map(project => ({
      ...project,
      services: project.services.sort((a, b) => a.localeCompare(b)),
    }))
    .sort((a, b) => a.project.localeCompare(b.project));

  return {
    version: 1,
    captured_at: new Date().toISOString(),
    tracked_count: trackedContainers.length,
    project_count: projects.length,
    containers: trackedContainers,
    projects,
  };
}

function getRestoreSnapshotSignature(snapshot) {
  if (!snapshot || !Array.isArray(snapshot.containers)) return '';
  return snapshot.containers
    .map(container => `${container.name}|${container.project || ''}|${container.service || ''}`)
    .sort()
    .join('\n');
}

async function readPersistedRestoreSnapshot() {
  if (restoreRuntime.snapshot) return restoreRuntime.snapshot;

  try {
    const raw = await fs.readFile(RESTORE_STATE_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.containers)) {
      throw new Error('invalid restore snapshot format');
    }
    restoreRuntime.snapshot = parsed;
    restoreRuntime.lastSnapshotSignature = getRestoreSnapshotSignature(parsed);
    return restoreRuntime.snapshot;
  } catch (e) {
    if (e.code !== 'ENOENT') {
      restoreRuntime.lastPersistError = e.message;
      console.error('Restore snapshot read error:', e.message);
    }
    return null;
  }
}

async function writePersistedRestoreSnapshot(snapshot) {
  await fs.mkdir(path.dirname(RESTORE_STATE_FILE), { recursive: true });
  const tmpFile = `${RESTORE_STATE_FILE}.tmp`;
  await fs.writeFile(tmpFile, JSON.stringify(snapshot, null, 2), 'utf8');
  await fs.rename(tmpFile, RESTORE_STATE_FILE);
  restoreRuntime.snapshot = snapshot;
  restoreRuntime.lastSnapshotSignature = getRestoreSnapshotSignature(snapshot);
  restoreRuntime.lastPersistedAt = Date.now();
  restoreRuntime.lastPersistError = null;
  return snapshot;
}

async function persistRestoreSnapshot(containers, { force = false } = {}) {
  const snapshot = buildRestoreSnapshot(containers);
  const signature = getRestoreSnapshotSignature(snapshot);

  if (!force && restoreRuntime.snapshot && signature === restoreRuntime.lastSnapshotSignature) {
    return restoreRuntime.snapshot;
  }

  try {
    return await writePersistedRestoreSnapshot(snapshot);
  } catch (e) {
    restoreRuntime.lastPersistError = e.message;
    throw e;
  }
}

async function syncRestoreSnapshotFromDocker(options = {}) {
  const containers = await fetchDocker('/containers/json?all=true');
  if (!Array.isArray(containers)) throw new Error('docker container list unavailable');
  return persistRestoreSnapshot(containers, options);
}

async function restoreContainersFromSnapshot(trigger = 'manual') {
  const snapshot = await readPersistedRestoreSnapshot();
  const result = {
    trigger,
    attempted_at: new Date().toISOString(),
    snapshot_found: Boolean(snapshot),
    snapshot_captured_at: snapshot?.captured_at || null,
    tracked_count: snapshot?.tracked_count || 0,
    started: [],
    already_running: [],
    missing: [],
    failed: [],
    ok: true,
    skipped: false,
    message: '',
  };

  if (!snapshot) {
    result.skipped = true;
    result.message = 'No hay snapshot persistido todavia.';
    restoreRuntime.lastRestoreResult = result;
    return result;
  }

  const containers = await fetchDocker('/containers/json?all=true');
  if (!Array.isArray(containers)) throw new Error('docker container list unavailable');

  const currentByName = new Map();
  containers.forEach(container => {
    currentByName.set(getContainerLabel(container), container);
  });

  for (const target of snapshot.containers) {
    const current = currentByName.get(target.name);
    if (!current) {
      result.missing.push(target.name);
      continue;
    }
    if (current.State === 'running') {
      result.already_running.push(target.name);
      continue;
    }

    try {
      await requestDocker(`/containers/${encodeURIComponent(target.name)}/start`, {
        method: 'POST',
        okStatuses: [204, 304],
        timeout: 10000,
      });
      result.started.push(target.name);
    } catch (e) {
      result.failed.push({ name: target.name, error: e.message });
      result.ok = false;
    }
  }

  if (!result.message) {
    result.message = result.failed.length > 0
      ? 'Se restauraron parcialmente los servicios activos.'
      : 'Restauracion completada.';
  }

  result.finished_at = new Date().toISOString();
  restoreRuntime.lastRestoreResult = result;
  return result;
}

function getRestoreStatePayload() {
  return {
    enabled: AUTO_RESTORE_ON_BOOT,
    startup_delay_ms: RESTORE_STARTUP_DELAY_MS,
    sync_interval_ms: RESTORE_SYNC_INTERVAL_MS,
    snapshot: restoreRuntime.snapshot,
    runtime: {
      last_persisted_at: restoreRuntime.lastPersistedAt
        ? new Date(restoreRuntime.lastPersistedAt).toISOString()
        : null,
      last_persist_error: restoreRuntime.lastPersistError,
      startup_restore: restoreRuntime.startupRestore,
      last_restore: restoreRuntime.lastRestoreResult,
    },
  };
}

async function runStartupRestore() {
  if (!AUTO_RESTORE_ON_BOOT) {
    restoreRuntime.startupRestore.status = 'disabled';
    return;
  }

  restoreRuntime.startupRestore.status = 'running';
  restoreRuntime.startupRestore.started_at = new Date().toISOString();
  restoreRuntime.startupRestore.error = null;

  for (let attempt = 1; attempt <= RESTORE_RETRY_COUNT; attempt++) {
    restoreRuntime.startupRestore.attempts = attempt;
    try {
      await readPersistedRestoreSnapshot();
      const result = await restoreContainersFromSnapshot('startup');
      restoreRuntime.startupRestore.finished_at = new Date().toISOString();
      restoreRuntime.startupRestore.status = result.skipped
        ? 'skipped'
        : (result.failed.length > 0 ? 'partial' : 'completed');
      restoreRuntime.startupRestore.error = result.failed.length > 0
        ? `${result.failed.length} contenedores no se pudieron arrancar`
        : null;
      return;
    } catch (e) {
      restoreRuntime.startupRestore.error = e.message;
      if (attempt === RESTORE_RETRY_COUNT) {
        restoreRuntime.startupRestore.status = 'failed';
        restoreRuntime.startupRestore.finished_at = new Date().toISOString();
        console.error('Startup restore failed:', e.message);
        return;
      }
      await sleep(RESTORE_RETRY_DELAY_MS);
    }
  }
}

async function restoreSnapshotLoop() {
  try {
    await syncRestoreSnapshotFromDocker();
  } catch (e) {
    restoreRuntime.lastPersistError = e.message;
    console.error('Restore snapshot sync error:', e.message);
  }
}

// Background monitor loop (every 15s)
async function alertMonitorLoop() {
  if (!TG_TOKEN || !TG_CHAT_ID) return;

  try {

    // System metrics check with resilience - require 3 consecutive failures before alerting
    const CONSECUTIVE_FAILURES_THRESHOLD = 3;
    let netdataConsecutiveFailures = 0;
    
    try {
      const base = NETDATA + '/api/v1/data?points=1&format=json&chart=';
      const [cpu, ram, disk] = await Promise.all([
        fetchJSON(base + 'system.cpu'),
        fetchJSON(base + 'system.ram'),
        fetchJSON(base + 'disk_space./'),
      ]);

      // Reset failure counter on success
      netdataConsecutiveFailures = 0;

      if (alertState.serverDown) {
        alertState.serverDown = false;
        alertState.consecutiveHighCpu = 0;
        alertState.consecutiveHighRam = 0;
        await sendAlert('server_up', 'Servidor Recuperado',
          'El servidor ha vuelto a estar en linea.');
      }

      if (cpu?.data?.[0]) {
        const total = cpu.data[0].slice(1).reduce((a, b) => a + b, 0);
        if (total > 90) {
          alertState.consecutiveHighCpu++;
          if (alertState.consecutiveHighCpu >= 2) {
            await sendAlert('cpu_high', 'CPU Critica',
              `Uso de CPU al <b>${total.toFixed(1)}%</b> de forma sostenida.`);
          }
        } else {
          alertState.consecutiveHighCpu = 0;
        }
      }

      if (ram?.data?.[0]) {
        const labels = ram.labels;
        const row = ram.data[0];
        const totalMB = row.slice(1).reduce((a, b) => a + b, 0);
        const usedMB = (row[labels.indexOf('active')] || 0) + (row[labels.indexOf('wired')] || 0) + (row[labels.indexOf('compressor')] || 0);
        const usedPct = totalMB > 0 ? (usedMB / totalMB) * 100 : 0;
        if (usedPct > 90) {
          alertState.consecutiveHighRam++;
          if (alertState.consecutiveHighRam >= 2) {
            await sendAlert('ram_high', 'Memoria Critica',
              `Uso de RAM al <b>${usedPct.toFixed(1)}%</b> (${(usedMB / 1024).toFixed(1)} GB usados).`);
          }
        } else {
          alertState.consecutiveHighRam = 0;
        }
      }

      if (disk?.data?.[0]) {
        const labels = disk.labels;
        const row = disk.data[0];
        const used = row[labels.indexOf('used')] || 0;
        const avail = row[labels.indexOf('avail')] || 0;
        const total = used + avail;
        const pct = total > 0 ? (used / total) * 100 : 0;
        if (pct > 85) {
          await sendAlert('disk_high', 'Disco Casi Lleno',
            `Uso de disco al <b>${pct.toFixed(1)}%</b> (${used.toFixed(1)} GB de ${total.toFixed(1)} GB).`);
        }
      }
    } catch (e) {
      netdataConsecutiveFailures++;
      console.error('Netdata check error:', e.message, '(failures:', netdataConsecutiveFailures + ')');
      
      // Only alert after 3 consecutive failures to reduce false positives
      if (netdataConsecutiveFailures >= CONSECUTIVE_FAILURES_THRESHOLD && !alertState.serverDown) {
        alertState.serverDown = true;
        await sendAlert('server_down', 'Servidor Caido',
          'No se puede conectar con Netdata tras multiples intentos.');
      }
      // Return early to skip container checks if Netdata is down
      return;
    }

    // 2. Check Docker containers
    try {
      const containers = await fetchDocker('/containers/json?all=true');
      if (Array.isArray(containers)) {
        const current = {};
        containers.forEach(c => {
          const name = getContainerLabel(c);
          current[name] = c.State;
        });

        for (const [name, prevState] of Object.entries(alertState.prevContainers)) {
          const newState = current[name];
          if (prevState === 'running' && (!newState || newState !== 'running')) {
            await sendAlert('container_down', 'Contenedor Caido',
              `El contenedor <b>${name}</b> ha dejado de funcionar.\nEstado: ${newState || 'eliminado'}`);
          }
          if (prevState && prevState !== 'running' && newState === 'running') {
            await sendAlert('container_up', 'Contenedor Recuperado',
              `El contenedor <b>${name}</b> ha vuelto a estar en funcionamiento.`);
          }
        }

        for (const c of containers) {
          const name = getContainerLabel(c);
          if (c.State === 'restarting') {
            await sendAlert('container_restart', 'Contenedor Reiniciandose',
              `El contenedor <b>${name}</b> esta reiniciandose continuamente.`);
          }
        }

        alertState.prevContainers = current;
      }
    } catch {}

    // 3. Check CrowdSec security (buffered → digest)
    try {
      const token = await getCrowdSecToken();
      if (token) {
        const alerts = await fetchJSON(
          CROWDSEC + '/v1/alerts?limit=10',
          { Authorization: 'Bearer ' + token }
        );
        if (Array.isArray(alerts)) {
          for (const a of alerts) {
            const id = a.id || a.created_at;
            if (!alertState.prevAlertIds.has(id)) {
              alertState.prevAlertIds.add(id);
              if (!isActionableCrowdSecAlert(a)) continue;
              const scenario = a.scenario || 'Desconocido';
              const source = normalizeIP(a.source?.ip || a.source?.value || a.source?.scope || '');
              const events = a.events_count || 0;
              securityDigest.alerts.push({ scenario, source, events, time: Date.now() });
              recordAttack({ ip: source, scenario, type: 'alert', events });
            }
          }
          if (alertState.prevAlertIds.size > 200) {
            const arr = [...alertState.prevAlertIds];
            alertState.prevAlertIds = new Set(arr.slice(-100));
          }
        }
      }

      if (CS_BOUNCER_KEY) {
        const decisions = await fetchJSON(
          CROWDSEC + '/v1/decisions',
          { 'X-Api-Key': CS_BOUNCER_KEY }
        );
        if (Array.isArray(decisions) && decisions.length > alertState.prevDecisionCount) {
          const newBans = decisions.length - alertState.prevDecisionCount;
          if (alertState.prevDecisionCount > 0) {
            const latest = decisions.slice(0, newBans);
            for (const d of latest) {
              securityDigest.bans.push({ ip: d.value || '?', type: d.type || 'ban', scenario: d.scenario || '?', duration: d.duration || '?', time: Date.now() });
              recordAttack({ ip: d.value || '', scenario: d.scenario || '', type: 'ban' });
            }
          }
          alertState.prevDecisionCount = decisions.length;
        } else if (Array.isArray(decisions)) {
          alertState.prevDecisionCount = decisions.length;
        }
      }

      // Check if under attack (immediate alert if threshold exceeded)
      if (securityDigest.alerts.length >= UNDER_ATTACK_THRESHOLD) {
        await sendUnderAttackAlert();
      }

      // Send digest if interval elapsed
      if (Date.now() - securityDigest.lastDigestSent >= DIGEST_INTERVAL) {
        await sendSecurityDigest();
      }
    } catch {}

  } catch (e) {
    console.error('Alert monitor error:', e.message);
  }
}

// Start alert loop
setTimeout(() => {
  alertMonitorLoop();
  setInterval(alertMonitorLoop, 15000);
}, 5000);

// Persist running services independently of Telegram alerts
setTimeout(() => {
  restoreSnapshotLoop();
  setInterval(restoreSnapshotLoop, RESTORE_SYNC_INTERVAL_MS);
}, 4000);

// --- Security middleware ---

// Security headers
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('X-XSS-Protection', '1; mode=block');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Basic rate limiter (in-memory, per IP)
const rateLimits = new Map();
const blockedIps = new Map();
const RATE_WINDOW = Number(process.env.RATE_WINDOW_MS || 60000); // 1 minute
const RATE_MAX = Number(process.env.RATE_MAX_REQUESTS || 240); // ~4 req/s per client
const RATE_BAN_MS = Number(process.env.RATE_BAN_MS || 15 * 60 * 1000); // 15 minutes
const RATE_LIMIT_BYPASS_IPS = new Set(
  String(process.env.RATE_LIMIT_BYPASS_IPS || '')
    .split(',')
    .map(v => normalizeIP(v))
    .filter(Boolean)
);

function getClientIP(req) {
  const remoteIP = normalizeIP(req.socket?.remoteAddress || req.connection?.remoteAddress || req.ip || '');
  const cameFromTrustedProxy = !remoteIP || isPrivateIP(remoteIP);

  if (cameFromTrustedProxy) {
    const cfIP = normalizeIP(req.headers['cf-connecting-ip']);
    if (net.isIP(cfIP)) return cfIP;

    const xff = req.headers['x-forwarded-for'];
    const xffIP = normalizeIP(Array.isArray(xff) ? xff[0] : xff);
    if (net.isIP(xffIP)) return xffIP;
  }

  if (net.isIP(remoteIP)) return remoteIP;
  return 'unknown';
}

app.use((req, res, next) => {
  const ip = getClientIP(req);
  req.clientIp = ip;

  if (RATE_LIMIT_BYPASS_IPS.has(ip)) return next();

  const now = Date.now();
  const blocked = blockedIps.get(ip);
  if (blocked && blocked.until > now) {
    const retryAfter = Math.max(1, Math.ceil((blocked.until - now) / 1000));
    res.set('Retry-After', String(retryAfter));
    return res.status(429).json({ error: 'Temporarily blocked due to high request rate' });
  }

  let entry = rateLimits.get(ip);
  if (!entry || now - entry.start > RATE_WINDOW) {
    entry = { start: now, count: 0 };
    rateLimits.set(ip, entry);
  }

  entry.count++;
  if (entry.count > RATE_MAX) {
    blockedIps.set(ip, { until: now + RATE_BAN_MS });
    const retryAfter = Math.max(1, Math.ceil(RATE_BAN_MS / 1000));
    res.set('Retry-After', String(retryAfter));
    return res.status(429).json({ error: 'Too many requests' });
  }

  next();
});

// Clean rate limit and temporary block maps periodically
setInterval(() => {
  const cutoff = Date.now() - RATE_WINDOW;
  const now = Date.now();
  for (const [ip, entry] of rateLimits) {
    if (entry.start < cutoff) rateLimits.delete(ip);
  }
  for (const [ip, entry] of blockedIps) {
    if (entry.until <= now) blockedIps.delete(ip);
  }
}, 60000);

// AIdentity auth via headers from Caddy forward_auth (X-Auth-User, X-Auth-Email, X-Auth-Role)
// Fallback to Basic Auth if no AIdentity headers (only when NOT behind Caddy)
app.use((req, res, next) => {
  const authUser = req.headers['x-auth-user'];
  const authEmail = req.headers['x-auth-email'];
  const authRole = req.headers['x-auth-role'];
  const isBehindProxy = req.headers['x-forwarded-host'] || req.headers['x-forwarded-for'];
  
  if (authUser) {
    // AIdentity auth - user is authenticated
    req.authUser = authUser;
    req.authEmail = authEmail;
    req.authRole = authRole;
    return next();
  }
  
  // If behind Caddy proxy and no AIdentity auth, return 401 without Basic Auth
  // so Caddy can handle the redirect to portal
  if (isBehindProxy) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  // Fallback to Basic Auth (if DASHBOARD_PASSWORD is set)
  if (!DASHBOARD_PASSWORD) {
    res.set('WWW-Authenticate', 'Basic realm="Monitor del Servidor"');
    return res.status(401).send('Unauthorized');
  }
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Basic ')) {
    const decoded = Buffer.from(auth.slice(6), 'base64').toString();
    const idx = decoded.indexOf(':');
    const pw = idx >= 0 ? decoded.slice(idx + 1) : '';
    if (pw.length > 0 && pw.length < 256 &&
        crypto.timingSafeEqual(Buffer.from(pw.padEnd(256)), Buffer.from(DASHBOARD_PASSWORD.padEnd(256)))) {
      return next();
    }
  }
  res.set('WWW-Authenticate', 'Basic realm="Monitor del Servidor"');
  res.status(401).send('Unauthorized');
});

function requireWriteAccess(req, res, next) {
  if (!req.authUser) return next();

  const role = String(req.authRole || '').toLowerCase();
  if (role === 'admin' || role === 'owner' || role === 'superadmin') return next();

  return res.status(403).json({ error: 'Admin role required' });
}

// Redirect old /login to root
app.get('/login', (req, res) => res.redirect('/'));

app.use(express.static(path.join(__dirname, 'public')));

// System metrics (CPU, RAM, disk, load, uptime, I/O, network)
app.get('/api/system', async (req, res) => {
  try {
    const base = NETDATA + '/api/v1/data?points=1&format=json&chart=';
    const [cpu, ram, disk, load, uptime, io, net] = await Promise.all([
      fetchJSON(base + 'system.cpu'),
      fetchJSON(base + 'system.ram'),
      fetchJSON(base + 'disk_space./'),
      fetchJSON(base + 'system.load'),
      fetchJSON(base + 'system.uptime'),
      fetchJSON(base + 'system.io'),
      fetchJSON(base + 'net.' + NET_IFACE),
    ]);
    res.json({ cpu, ram, disk, load, uptime, io, net });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// Storage - all disk mount points with I/O
app.get('/api/storage', async (req, res) => {
  try {
    const charts = await fetchJSON(NETDATA + '/api/v1/charts');
    const allCharts = charts?.charts || {};

    // Disk space charts
    const diskCharts = Object.entries(allCharts)
      .filter(([k]) => k.startsWith('disk_space.'))
      .map(([k, v]) => ({ id: k, name: v.name, family: v.family, title: v.title, mount: k.replace('disk_space.', '') }));

    // Disk I/O charts (disk.* and disk_ops.*)
    const ioCharts = Object.entries(allCharts)
      .filter(([k]) => k.match(/^disk\.[a-z]/) && !k.startsWith('disk_'))
      .map(([k, v]) => ({ id: k, family: v.family }));

    // Disk inode charts
    const inodeCharts = Object.entries(allCharts)
      .filter(([k]) => k.startsWith('disk_inodes.'))
      .map(([k, v]) => ({ id: k, family: v.family, mount: k.replace('disk_inodes.', '') }));

    const base = NETDATA + '/api/v1/data?points=1&format=json&chart=';

    // Fetch all in parallel
    const [spaceData, ioData, inodeData] = await Promise.all([
      Promise.all(diskCharts.map(async (c) => {
        try {
          const d = await fetchJSON(base + c.id);
          const labels = d?.labels || [];
          const row = d?.data?.[0] || [];
          const used = row[labels.indexOf('used')] || 0;
          const avail = row[labels.indexOf('avail')] || 0;
          const reserved = row[labels.indexOf('reserved_for_root')] || 0;
          const total = used + avail + reserved;
          return { mount: c.mount === '/' ? '/' : c.mount.replace(/\./g, '/'), family: c.family, used, avail, reserved, total, percent: total > 0 ? (used / total) * 100 : 0 };
        } catch { return null; }
      })),
      Promise.all(ioCharts.slice(0, 10).map(async (c) => {
        try {
          const d = await fetchJSON(base + c.id);
          const labels = d?.labels || [];
          const row = d?.data?.[0] || [];
          return { family: c.family, reads: Math.abs(row[labels.indexOf('reads')] || 0), writes: Math.abs(row[labels.indexOf('writes')] || 0) };
        } catch { return null; }
      })),
      Promise.all(inodeCharts.slice(0, 10).map(async (c) => {
        try {
          const d = await fetchJSON(base + c.id);
          const labels = d?.labels || [];
          const row = d?.data?.[0] || [];
          const used = row[labels.indexOf('used')] || 0;
          const avail = row[labels.indexOf('avail')] || 0;
          return { mount: c.mount === '/' ? '/' : c.mount.replace(/\./g, '/'), used_inodes: used, avail_inodes: avail, percent_inodes: (used + avail) > 0 ? (used / (used + avail)) * 100 : 0 };
        } catch { return null; }
      })),
    ]);

    // Merge data
    const result = spaceData.filter(Boolean).map(s => {
      const io = ioData.filter(Boolean).find(i => i.family === s.family);
      const inode = inodeData.filter(Boolean).find(i => i.mount === s.mount);
      return {
        ...s,
        io_reads: io?.reads || 0,
        io_writes: io?.writes || 0,
        used_inodes: inode?.used_inodes || 0,
        avail_inodes: inode?.avail_inodes || 0,
        percent_inodes: inode?.percent_inodes || 0,
      };
    });

    res.json(result);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// Swap memory
app.get('/api/swap', async (req, res) => {
  try {
    const data = await fetchJSON(NETDATA + '/api/v1/data?points=1&format=json&chart=mem.swap');
    res.json(data);
  } catch (e) {
    res.json(null);
  }
});

// Per-core CPU usage
app.get('/api/cpu-cores', async (req, res) => {
  try {
    const charts = await fetchJSON(NETDATA + '/api/v1/charts');
    const cpuCharts = Object.keys(charts?.charts || {})
      .filter(k => k.match(/^cpu\.cpu\d+$/))
      .sort((a, b) => {
        const na = parseInt(a.replace('cpu.cpu', ''));
        const nb = parseInt(b.replace('cpu.cpu', ''));
        return na - nb;
      });

    const base = NETDATA + '/api/v1/data?points=1&format=json&chart=';
    const coreData = await Promise.all(
      cpuCharts.slice(0, 32).map(async (chartId) => {
        try {
          const d = await fetchJSON(base + chartId);
          const row = d?.data?.[0] || [];
          const total = row.slice(1).reduce((a, b) => a + b, 0);
          return { core: chartId.replace('cpu.', ''), usage: Math.min(100, Math.max(0, total)) };
        } catch {
          return null;
        }
      })
    );
    res.json(coreData.filter(Boolean));
  } catch (e) {
    res.json([]);
  }
});

// TCP/UDP connection stats
app.get('/api/connections', async (req, res) => {
  try {
    const base = NETDATA + '/api/v1/data?points=1&format=json&chart=';
    const [tcp, udp, tcp6, udp6] = await Promise.all([
      fetchJSON(base + 'ipv4.sockstat_tcp_sockets').catch(() => null),
      fetchJSON(base + 'ipv4.sockstat_udp_sockets').catch(() => null),
      fetchJSON(base + 'ipv6.sockstat6_tcp_sockets').catch(() => null),
      fetchJSON(base + 'ipv6.sockstat6_udp_sockets').catch(() => null),
    ]);

    const result = { tcp: {}, udp: {}, tcp6: {}, udp6: {} };

    if (tcp?.data?.[0] && tcp.labels) {
      tcp.labels.forEach((l, i) => { if (i > 0) result.tcp[l] = tcp.data[0][i] || 0; });
    }
    if (udp?.data?.[0] && udp.labels) {
      udp.labels.forEach((l, i) => { if (i > 0) result.udp[l] = udp.data[0][i] || 0; });
    }
    if (tcp6?.data?.[0] && tcp6.labels) {
      tcp6.labels.forEach((l, i) => { if (i > 0) result.tcp6[l] = tcp6.data[0][i] || 0; });
    }
    if (udp6?.data?.[0] && udp6.labels) {
      udp6.labels.forEach((l, i) => { if (i > 0) result.udp6[l] = udp6.data[0][i] || 0; });
    }

    res.json(result);
  } catch (e) {
    res.json({});
  }
});

// Disk I/O per device
app.get('/api/disk-io', async (req, res) => {
  try {
    const charts = await fetchJSON(NETDATA + '/api/v1/charts');
    const ioCharts = Object.entries(charts?.charts || {})
      .filter(([k]) => k.match(/^disk\.[a-z]/) && !k.startsWith('disk_'))
      .map(([k, v]) => ({ id: k, family: v.family, title: v.title }));

    const base = NETDATA + '/api/v1/data?points=1&format=json&chart=';
    const data = await Promise.all(
      ioCharts.slice(0, 10).map(async (c) => {
        try {
          const d = await fetchJSON(base + c.id);
          const labels = d?.labels || [];
          const row = d?.data?.[0] || [];
          return {
            device: c.family || c.id.replace('disk.', ''),
            reads: Math.abs(row[labels.indexOf('reads')] || 0),
            writes: Math.abs(row[labels.indexOf('writes')] || 0),
          };
        } catch { return null; }
      })
    );
    res.json(data.filter(Boolean));
  } catch (e) {
    res.json([]);
  }
});

// Alert status and history
app.get('/api/alerts/status', (req, res) => {
  res.json({
    configured: !!(TG_TOKEN && TG_CHAT_ID),
    telegramOk: alertState.telegramOk,
    serverDown: alertState.serverDown,
    history: alertState.history.slice(0, 30),
    cooldowns: Object.entries(alertState.lastSent).map(([type, time]) => ({
      type, lastSent: time, cooldown: COOLDOWNS[type] || 60000, canSend: canSendAlert(type),
    })),
    healthcheck: {
      configured: !!HC_PING_URL,
      lastPing: lastHeartbeat,
      ok: heartbeatOk,
    },
  });
});

// Test Telegram alert
app.post('/api/alerts/test', async (req, res) => {
  if (!TG_TOKEN || !TG_CHAT_ID) {
    return res.json({ ok: false, error: 'Telegram no configurado. Anade TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID al .env' });
  }
  const ok = await sendTelegram('\u{1F9EA} <b>Test de Alertas</b>\n\nSi recibes este mensaje, las alertas de tu servidor estan funcionando correctamente.\n\n<i>' + new Date().toLocaleString('es-ES') + '</i>');
  alertState.telegramOk = ok;
  res.json({ ok, error: ok ? null : 'No se pudo enviar el mensaje. Verifica el token y chat ID.' });
});

// Netdata host info
app.get('/api/info', async (req, res) => {
  try {
    const info = await fetchJSON(NETDATA + '/api/v1/info');
    res.json(info);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// Netdata alarms
app.get('/api/alarms', async (req, res) => {
  try {
    const alarms = await fetchJSON(NETDATA + '/api/v1/alarms');
    res.json(alarms);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// Docker containers
app.get('/api/docker', async (req, res) => {
  try {
    const containers = await fetchDocker('/containers/json?all=true');
    res.json(containers);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/restore-state', async (req, res) => {
  try {
    await readPersistedRestoreSnapshot();
    res.json(getRestoreStatePayload());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/restore-state/snapshot', requireWriteAccess, async (req, res) => {
  try {
    await syncRestoreSnapshotFromDocker({ force: true });
    res.json(getRestoreStatePayload());
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.post('/api/restore-state/restore', requireWriteAccess, async (req, res) => {
  try {
    await readPersistedRestoreSnapshot();
    await restoreContainersFromSnapshot('manual');
    setTimeout(() => { restoreSnapshotLoop(); }, 3000);
    res.json(getRestoreStatePayload());
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// CrowdSec security info
app.get('/api/security', async (req, res) => {
  try {
    const results = { health: null, alerts: null, decisions: null };
    try { results.health = await fetchJSON(CROWDSEC + '/health'); } catch {}
    try {
      const token = await getCrowdSecToken();
      if (token) {
        results.alerts = await fetchJSON(CROWDSEC + '/v1/alerts?limit=15', { Authorization: 'Bearer ' + token });
        if (results.alerts && results.alerts.code === 401) { csToken = null; csTokenExpiry = 0; }
        if (Array.isArray(results.alerts)) {
          results.alerts = results.alerts.filter(isActionableCrowdSecAlert);
        }
      }
    } catch {}
    if (CS_BOUNCER_KEY) {
      try {
        results.decisions = await fetchJSON(CROWDSEC + '/v1/decisions', { 'X-Api-Key': CS_BOUNCER_KEY });
        if (Array.isArray(results.decisions)) results.decisions = results.decisions.slice(0, 200);
      } catch {}
    }
    res.json(results);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// Security with geolocation
app.get('/api/security-geo', async (req, res) => {
  try {
    let alerts = [], decisions = [];
    try {
      const token = await getCrowdSecToken();
      if (token) {
        const data = await fetchJSON(CROWDSEC + '/v1/alerts?limit=50', { Authorization: 'Bearer ' + token });
        if (Array.isArray(data)) alerts = data.filter(isActionableCrowdSecAlert);
      }
    } catch {}
    if (CS_BOUNCER_KEY) {
      try {
        const data = await fetchJSON(CROWDSEC + '/v1/decisions', { 'X-Api-Key': CS_BOUNCER_KEY });
        if (Array.isArray(data)) decisions = data.slice(0, 300);
      } catch {}
    }

    const ipSet = new Set();
    alerts.forEach(a => { if (a.source?.ip) ipSet.add(a.source.ip); });
    decisions.forEach(d => { if (d.value) ipSet.add(d.value); });
    const uniqueIps = [...ipSet];

    const geoResults = uniqueIps.length > 0 ? await geoLookupBatch(uniqueIps) : [];
    const geoMap = {};
    geoResults.forEach(g => { geoMap[g.ip] = g; });

    // Country stats
    const countryStats = {};
    geoResults.forEach(g => {
      const code = g.countryCode || '--';
      if (code === 'LO' || code === '--') return;
      if (!countryStats[code]) countryStats[code] = { country: g.country, code, count: 0, ips: [] };
      countryStats[code].count++;
      if (countryStats[code].ips.length < 5) countryStats[code].ips.push(g.ip);
    });

    // Aggregate map points by location
    const pointMap = {};
    geoResults.filter(g => g.lat && g.lon && g.lat !== 0).forEach(g => {
      const key = g.lat.toFixed(1) + ',' + g.lon.toFixed(1);
      if (!pointMap[key]) pointMap[key] = { lat: g.lat, lon: g.lon, count: 0, ips: [], country: g.country, city: g.city };
      pointMap[key].count++;
      if (pointMap[key].ips.length < 3) pointMap[key].ips.push(g.ip);
    });

    res.json({
      alerts: alerts.slice(0, 20).map(a => ({
        id: a.id, scenario: a.scenario, created_at: a.created_at,
        source_ip: a.source?.ip, events_count: a.events_count,
        geo: a.source?.ip ? geoMap[a.source.ip] || null : null,
      })),
      decisions: decisions.slice(0, 30).map(d => ({
        value: d.value, type: d.type, scenario: d.scenario, duration: d.duration,
        geo: d.value ? geoMap[d.value] || null : null,
      })),
      mapPoints: Object.values(pointMap),
      countryStats: Object.values(countryStats).sort((a, b) => b.count - a.count),
      totalIps: uniqueIps.length,
    });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// IP detail info
app.get('/api/ip-info/:ip', async (req, res) => {
  try {
    const ip = req.params.ip;
    // Validate IP format (IPv4 or IPv6)
    if (!/^[\d.]+$/.test(ip) && !/^[a-fA-F0-9:]+$/.test(ip)) {
      return res.status(400).json({ error: 'Invalid IP format' });
    }
    const results = await geoLookupBatch([ip]);
    const geo = results[0] || { ip, country: 'Desconocido' };

    // Find related alerts/decisions from CrowdSec
    let relatedAlerts = [], relatedDecisions = [];
    try {
      const token = await getCrowdSecToken();
      if (token) {
        const alerts = await fetchJSON(CROWDSEC + '/v1/alerts?limit=50', { Authorization: 'Bearer ' + token });
        if (Array.isArray(alerts)) relatedAlerts = alerts.filter(a => isActionableCrowdSecAlert(a) && a.source?.ip === ip);
      }
    } catch {}
    if (CS_BOUNCER_KEY) {
      try {
        const decs = await fetchJSON(CROWDSEC + '/v1/decisions', { 'X-Api-Key': CS_BOUNCER_KEY });
        if (Array.isArray(decs)) relatedDecisions = decs.filter(d => d.value === ip);
      } catch {}
    }

    // History from our records
    const history = attackHistory.filter(h => h.ip === ip).slice(0, 20);

    res.json({
      ...geo,
      alerts: relatedAlerts.map(a => ({ scenario: a.scenario, created_at: a.created_at, events_count: a.events_count })),
      decisions: relatedDecisions.map(d => ({ type: d.type, scenario: d.scenario, duration: d.duration })),
      history,
    });
  } catch (e) {
    res.json({ ip: req.params.ip, error: e.message });
  }
});

// Attack stats (timeline)
app.get('/api/attack-stats', async (req, res) => {
  try {
    const now = Date.now();
    let alerts = [];
    try {
      const token = await getCrowdSecToken();
      if (token) {
        const data = await fetchJSON(CROWDSEC + '/v1/alerts?limit=200', { Authorization: 'Bearer ' + token });
        if (Array.isArray(data)) alerts = data.filter(isActionableCrowdSecAlert);
      }
    } catch {}

    // Daily (7 days)
    const daily = [];
    for (let d = 6; d >= 0; d--) {
      const date = new Date(now - d * 86400000);
      const key = date.toISOString().slice(0, 10);
      const label = date.toLocaleDateString('es-ES', { weekday: 'short', day: 'numeric' });
      daily.push({ date: key, label, count: 0 });
    }
    alerts.forEach(a => {
      if (a.created_at) {
        const key = new Date(a.created_at).toISOString().slice(0, 10);
        const entry = daily.find(d => d.date === key);
        if (entry) entry.count++;
      }
    });
    attackHistory.forEach(a => {
      const key = new Date(a.time).toISOString().slice(0, 10);
      const entry = daily.find(d => d.date === key);
      if (entry) entry.count++;
    });

    // Hourly (24h)
    const hourly = [];
    for (let h = 23; h >= 0; h--) {
      const t = new Date(now - h * 3600000);
      hourly.push({ hour: t.getHours() + ':00', count: 0 });
    }
    alerts.forEach(a => {
      if (a.created_at) {
        const diff = now - new Date(a.created_at).getTime();
        if (diff < 24 * 3600000 && diff >= 0) {
          const idx = 23 - Math.floor(diff / 3600000);
          if (idx >= 0 && idx < 24) hourly[idx].count++;
        }
      }
    });

    // Scenario breakdown
    const scenarios = {};
    alerts.forEach(a => {
      const s = a.scenario || 'desconocido';
      scenarios[s] = (scenarios[s] || 0) + (a.events_count || 1);
    });

    res.json({
      daily,
      hourly,
      scenarios: Object.entries(scenarios).sort((a, b) => b[1] - a[1]).slice(0, 10),
      totalAlerts: alerts.length,
    });
  } catch (e) {
    res.json({ daily: [], hourly: [], scenarios: [], totalAlerts: 0 });
  }
});

// CPU history
app.get('/api/cpu-history', async (req, res) => {
  try {
    res.json(await fetchJSON(NETDATA + '/api/v1/data?chart=system.cpu&after=-60&points=60&format=json&group=average'));
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// Network history
app.get('/api/net-history', async (req, res) => {
  try {
    res.json(await fetchJSON(NETDATA + '/api/v1/data?chart=net.' + NET_IFACE + '&after=-60&points=60&format=json&group=average'));
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// Disk I/O history
app.get('/api/io-history', async (req, res) => {
  try {
    res.json(await fetchJSON(NETDATA + '/api/v1/data?chart=system.io&after=-60&points=60&format=json&group=average'));
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// Top processes
app.get('/api/processes', async (req, res) => {
  try {
    const [cpuAll, memAll] = await Promise.all([
      fetchJSON(NETDATA + '/api/v1/allmetrics?format=json&filter=app.*cpu_utilization', {}, 8000),
      fetchJSON(NETDATA + '/api/v1/allmetrics?format=json&filter=app.*mem_private*', {}, 8000),
    ]);
    const procs = {};
    if (cpuAll && typeof cpuAll === 'object') {
      Object.entries(cpuAll).forEach(([chart, info]) => {
        const name = chart.replace('app.', '').replace('_cpu_utilization', '');
        const cpu = Object.values(info.dimensions || {}).reduce((sum, d) => sum + (d.value || 0), 0);
        if (cpu > 0.01) procs[name] = { name, cpu, mem: 0 };
      });
    }
    if (memAll && typeof memAll === 'object') {
      Object.entries(memAll).forEach(([chart, info]) => {
        const name = chart.replace('app.', '').replace('_mem_private_usage', '');
        const mem = Object.values(info.dimensions || {}).reduce((sum, d) => sum + (d.value || 0), 0);
        if (procs[name]) procs[name].mem = mem;
        else if (mem > 1) procs[name] = { name, cpu: 0, mem };
      });
    }
    res.json(Object.values(procs).sort((a, b) => b.cpu - a.cpu).slice(0, 15));
  } catch (e) { res.json([]); }
});

// System event log
app.get('/api/logs', async (req, res) => {
  try {
    const log = await fetchJSON(NETDATA + '/api/v1/alarm_log?after=0&last=30');
    res.json(Array.isArray(log) ? log : []);
  } catch (e) { res.json([]); }
});

// Network interfaces
app.get('/api/network-interfaces', async (req, res) => {
  try {
    const charts = await fetchJSON(NETDATA + '/api/v1/charts');
    const netCharts = Object.entries(charts?.charts || {})
      .filter(([k]) => k.startsWith('net.') && !k.startsWith('net_'))
      .map(([k, v]) => ({ id: k, name: v.name, family: v.family, title: v.title }));
    const base = NETDATA + '/api/v1/data?points=1&format=json&chart=';
    const data = await Promise.all(
      netCharts.slice(0, 8).map(async (c) => {
        try { return { ...c, data: await fetchJSON(base + c.id) }; }
        catch { return { ...c, data: null }; }
      })
    );
    res.json(data);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// Docker container stats
app.get('/api/docker/:id/stats', async (req, res) => {
  try {
    const id = req.params.id;
    // Validate Docker container ID (hex string, 12-64 chars)
    if (!/^[a-fA-F0-9]{12,64}$/.test(id)) {
      return res.status(400).json({ error: 'Invalid container ID' });
    }
    const [stats, inspect] = await Promise.all([
      fetchDocker(`/containers/${id}/stats?stream=false`),
      fetchDocker(`/containers/${id}/json`),
    ]);

    let cpuPercent = 0;
    if (stats.cpu_stats && stats.precpu_stats) {
      const cpuDelta = (stats.cpu_stats.cpu_usage?.total_usage || 0) - (stats.precpu_stats.cpu_usage?.total_usage || 0);
      const sysDelta = (stats.cpu_stats.system_cpu_usage || 0) - (stats.precpu_stats.system_cpu_usage || 0);
      const cpuCount = stats.cpu_stats.online_cpus || stats.cpu_stats.cpu_usage?.percpu_usage?.length || 1;
      if (sysDelta > 0 && cpuDelta >= 0) cpuPercent = (cpuDelta / sysDelta) * cpuCount * 100;
    }

    const memUsage = stats.memory_stats?.usage || 0;
    const memLimit = stats.memory_stats?.limit || 0;
    const memCache = stats.memory_stats?.stats?.cache || stats.memory_stats?.stats?.inactive_file || 0;
    const memActual = memUsage - memCache;

    let netRx = 0, netTx = 0;
    if (stats.networks) Object.values(stats.networks).forEach(n => { netRx += n.rx_bytes || 0; netTx += n.tx_bytes || 0; });

    let blockRead = 0, blockWrite = 0;
    if (stats.blkio_stats?.io_service_bytes_recursive) {
      stats.blkio_stats.io_service_bytes_recursive.forEach(e => {
        if (e.op === 'read' || e.op === 'Read') blockRead += e.value || 0;
        if (e.op === 'write' || e.op === 'Write') blockWrite += e.value || 0;
      });
    }

    const ports = inspect.NetworkSettings?.Ports || {};
    const portList = Object.entries(ports).map(([container, host]) => ({
      container, host: host?.[0] ? `${host[0].HostIp || '0.0.0.0'}:${host[0].HostPort}` : null,
    }));

    res.json({
      cpu_percent: cpuPercent,
      mem_usage: memActual, mem_limit: memLimit,
      mem_percent: memLimit > 0 ? (memActual / memLimit) * 100 : 0,
      net_rx: netRx, net_tx: netTx,
      block_read: blockRead, block_write: blockWrite,
      pids: stats.pids_stats?.current || 0,
      ports: portList,
      created: inspect.Created || '', started: inspect.State?.StartedAt || '',
      image: inspect.Config?.Image || '',
      cmd: (inspect.Config?.Cmd || []).join(' '),
      env: (inspect.Config?.Env || []).filter(e => !e.startsWith('PATH=') && !e.startsWith('HOME=') && !e.startsWith('HOSTNAME=')).slice(0, 10),
      restart_count: inspect.RestartCount || 0,
      restart_policy: inspect.HostConfig?.RestartPolicy?.Name || '',
    });
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// Docker all containers summary stats
app.get('/api/docker-stats', async (req, res) => {
  try {
    const containers = await fetchDocker('/containers/json');
    if (!Array.isArray(containers)) { res.json([]); return; }
    const stats = await Promise.all(
      containers.slice(0, 30).map(async (c) => {
        try {
          const s = await fetchDocker(`/containers/${c.Id}/stats?stream=false`);
          let cpuPercent = 0;
          if (s.cpu_stats && s.precpu_stats) {
            const cpuDelta = (s.cpu_stats.cpu_usage?.total_usage || 0) - (s.precpu_stats.cpu_usage?.total_usage || 0);
            const sysDelta = (s.cpu_stats.system_cpu_usage || 0) - (s.precpu_stats.system_cpu_usage || 0);
            if (sysDelta > 0) cpuPercent = (cpuDelta / sysDelta) * (s.cpu_stats.online_cpus || 1) * 100;
          }
          const memUsage = s.memory_stats?.usage || 0;
          const memCache = s.memory_stats?.stats?.cache || s.memory_stats?.stats?.inactive_file || 0;
          let netRx = 0, netTx = 0;
          if (s.networks) Object.values(s.networks).forEach(n => { netRx += n.rx_bytes || 0; netTx += n.tx_bytes || 0; });
          return {
            id: c.Id, name: getContainerLabel(c),
            cpu_percent: cpuPercent, mem_usage: memUsage - memCache, mem_limit: s.memory_stats?.limit || 0,
            net_rx: netRx, net_tx: netTx, pids: s.pids_stats?.current || 0,
          };
        } catch { return null; }
      })
    );
    res.json(stats.filter(Boolean));
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// Extended system info
app.get('/api/system-info', async (req, res) => {
  try {
    const info = await fetchJSON(NETDATA + '/api/v1/info');
    res.json({
      hostname: info.hostname || '', os_name: info.os_name || '', os_version: info.os_version || '',
      kernel: info.kernel_name || '', kernel_version: info.kernel_version || '',
      architecture: info.architecture || '', cores: info.cores_total || 0,
      ram_total: info.ram_total || 0, disk_total: info.total_disk_space || 0,
      mirrored_hosts: info.mirrored_hosts || [], container: info.container || '',
      virtualization: info.virtualization || '', cloud_provider: info.cloud_provider_type || '',
    });
  } catch (e) { res.status(502).json({ error: e.message }); }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server Monitor running on port ${PORT}`);
  console.log(`Telegram alerts: ${TG_TOKEN && TG_CHAT_ID ? 'ENABLED' : 'DISABLED'}`);
  console.log(`Healthcheck heartbeat: ${HC_PING_URL ? 'ENABLED' : 'DISABLED'}`);
  console.log(`Auto-restore: ${AUTO_RESTORE_ON_BOOT ? `ENABLED (${RESTORE_STATE_FILE})` : 'DISABLED'}`);
  readPersistedRestoreSnapshot().catch(() => {});
  if (AUTO_RESTORE_ON_BOOT) {
    setTimeout(() => {
      runStartupRestore().catch(e => {
        restoreRuntime.startupRestore.status = 'failed';
        restoreRuntime.startupRestore.finished_at = new Date().toISOString();
        restoreRuntime.startupRestore.error = e.message;
        console.error('Startup restore failed:', e.message);
      });
    }, RESTORE_STARTUP_DELAY_MS);
  }
});
