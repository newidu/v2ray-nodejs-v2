const os = require('os');
const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { exec, execSync } = require('child_process');
const { WebSocket, createWebSocketStream } = require('ws');

// ======================== ENVIRONMENT VARIABLES ========================
const UUID = process.env.UUID || 'grok';
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';
const NEZHA_PORT = process.env.NEZHA_PORT || '';
const NEZHA_KEY = process.env.NEZHA_KEY || '';
const DOMAIN = process.env.DOMAIN || 'grok.alwaysdata.net';
const AUTO_ACCESS = process.env.AUTO_ACCESS || true;
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);
const SUB_PATH = process.env.SUB_PATH || 'sub';
const NAME = process.env.NAME || 'grok';
const PORT = process.env.PORT || 8305;
const ADMIN_PASS = process.env.ADMIN_PASS || 'grok';   // Admin password

// ======================== GLOBAL STATE ========================
let stats = {
  daily: { date: getCurrentDate(), upload: 0, download: 0 },
  monthly: { month: getCurrentMonth(), upload: 0, download: 0 },
  total: { upload: 0, download: 0 },
  last24h: []  // array of { timestamp, upload, download }
};
let networkLogs = [];        // max 1000 entries
let recordingEnabled = true; // network logging on/off
let limits = {
  daily: 0,      // bytes (0 = unlimited)
  monthly: 0,
  total: 0
};

// Admin session tokens (simple in-memory)
let adminTokens = new Map(); // token -> expiry timestamp

// Persistence files
const STATS_FILE = path.join(__dirname, 'stats.json');
const LOGS_FILE = path.join(__dirname, 'logs.json');
const LIMITS_FILE = path.join(__dirname, 'limits.json');

// ======================== UTILITY FUNCTIONS ========================
function getCurrentDate() {
  return new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Colombo' });
}
function getCurrentMonth() {
  return new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Colombo' }).slice(0, 7);
}
function getCurrentHour() {
  return new Date().toLocaleString('en-CA', { timeZone: 'Asia/Colombo', hour12: false }).slice(0, 13);
}

// Load/Save stats
function loadStats() {
  try {
    if (fs.existsSync(STATS_FILE)) {
      const data = JSON.parse(fs.readFileSync(STATS_FILE, 'utf8'));
      stats = { ...stats, ...data };
      // Ensure date/month match current; if not, rotate later
    }
  } catch (e) {}
}
function saveStats() {
  fs.writeFileSync(STATS_FILE, JSON.stringify(stats, null, 2));
}
function loadLogs() {
  try {
    if (fs.existsSync(LOGS_FILE)) {
      networkLogs = JSON.parse(fs.readFileSync(LOGS_FILE, 'utf8'));
      if (networkLogs.length > 1000) networkLogs = networkLogs.slice(-1000);
    }
  } catch (e) {}
}
function saveLogs() {
  fs.writeFileSync(LOGS_FILE, JSON.stringify(networkLogs.slice(-1000), null, 2));
}
function loadLimits() {
  try {
    if (fs.existsSync(LIMITS_FILE)) {
      limits = JSON.parse(fs.readFileSync(LIMITS_FILE, 'utf8'));
    }
  } catch (e) {}
}
function saveLimits() {
  fs.writeFileSync(LIMITS_FILE, JSON.stringify(limits, null, 2));
}

// Rotate daily/monthly stats when date/month changes
function rotateStatsIfNeeded() {
  const today = getCurrentDate();
  const thisMonth = getCurrentMonth();
  let changed = false;
  if (stats.daily.date !== today) {
    // Reset daily
    stats.daily = { date: today, upload: 0, download: 0 };
    changed = true;
  }
  if (stats.monthly.month !== thisMonth) {
    stats.monthly = { month: thisMonth, upload: 0, download: 0 };
    changed = true;
  }
  if (changed) saveStats();
}

// Update traffic counters (upload = from client to target, download = from target to client)
function updateStats(uploadBytes, downloadBytes) {
  rotateStatsIfNeeded();
  stats.daily.upload += uploadBytes;
  stats.daily.download += downloadBytes;
  stats.monthly.upload += uploadBytes;
  stats.monthly.download += downloadBytes;
  stats.total.upload += uploadBytes;
  stats.total.download += downloadBytes;

  // Update last24h (aggregate by hour)
  const currentHour = getCurrentHour();
  const existing = stats.last24h.find(h => h.hour === currentHour);
  if (existing) {
    existing.upload += uploadBytes;
    existing.download += downloadBytes;
  } else {
    stats.last24h.push({ hour: currentHour, upload: uploadBytes, download: downloadBytes });
    // Keep only last 24 hours
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
    stats.last24h = stats.last24h.filter(h => new Date(h.hour) > cutoff);
  }
  saveStats();
}

// Check if any limit is exceeded
function isLimitExceeded() {
  if (limits.daily > 0 && (stats.daily.upload + stats.daily.download) > limits.daily) return true;
  if (limits.monthly > 0 && (stats.monthly.upload + stats.monthly.download) > limits.monthly) return true;
  if (limits.total > 0 && (stats.total.upload + stats.total.download) > limits.total) return true;
  return false;
}

// Add a connection log (if recording enabled)
function addNetworkLog(entry) {
  if (!recordingEnabled) return;
  networkLogs.unshift(entry); // newest first
  if (networkLogs.length > 1000) networkLogs.pop();
  saveLogs();
}

// ======================== DNS RESOLUTION ========================
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];
function resolveHost(host) {
  return new Promise((resolve, reject) => {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
      resolve(host);
      return;
    }
    let attempts = 0;
    function tryNextDNS() {
      if (attempts >= DNS_SERVERS.length) {
        reject(new Error(`Failed to resolve ${host}`));
        return;
      }
      const dnsServer = DNS_SERVERS[attempts++];
      axios.get(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, { timeout: 5000 })
        .then(resp => {
          const data = resp.data;
          if (data.Status === 0 && data.Answer) {
            const ip = data.Answer.find(record => record.type === 1);
            if (ip) { resolve(ip.data); return; }
          }
          tryNextDNS();
        })
        .catch(() => tryNextDNS());
    }
    tryNextDNS();
  });
}

// ======================== PROXY WITH TRAFFIC COUNTING & LOGGING ========================
function proxyWithCounting(ws, targetHost, targetPort, protocol, clientIP, initialData) {
  const startTime = Date.now();
  let uploadBytes = 0;
  let downloadBytes = 0;

  const duplex = createWebSocketStream(ws, { decodeStrings: false, encoding: null });
  let socket = null;

  const onSocketConnect = () => {
    if (initialData && initialData.length) {
      socket.write(initialData);
      uploadBytes += initialData.length;
    }
    // Pipe with counting
    duplex.on('data', (chunk) => {
      uploadBytes += chunk.length;
      if (socket && !socket.destroyed) socket.write(chunk);
    });
    socket.on('data', (chunk) => {
      downloadBytes += chunk.length;
      if (!duplex.destroyed) duplex.write(chunk);
    });
    duplex.on('error', () => {});
    socket.on('error', () => {});
    duplex.on('close', () => {
      if (!socket.destroyed) socket.destroy();
      finalize();
    });
    socket.on('close', () => {
      if (!duplex.destroyed) duplex.destroy();
      finalize();
    });
  };

  const finalize = () => {
    const duration = (Date.now() - startTime) / 1000;
    updateStats(uploadBytes, downloadBytes);
    addNetworkLog({
      timestamp: new Date().toISOString(),
      clientIP,
      target: `${targetHost}:${targetPort}`,
      protocol,
      uploadBytes,
      downloadBytes,
      duration: duration.toFixed(2)
    });
  };

  const connectAndPipe = (hostToConnect) => {
    socket = net.connect({ host: hostToConnect, port: targetPort }, onSocketConnect);
    socket.on('error', (err) => {
      duplex.destroy();
      finalize();
    });
  };

  resolveHost(targetHost)
    .then(resolvedIP => connectAndPipe(resolvedIP))
    .catch(() => connectAndPipe(targetHost));
}

// ======================== VLESS & TROJAN HANDLERS (with counting integration) ========================
const uuidBytes = UUID.replace(/-/g, "");

function handleVlessConnection(ws, msg, clientIP) {
  const [VERSION] = msg;
  const id = msg.slice(1, 17);
  if (!id.every((v, i) => v == parseInt(uuidBytes.substr(i * 2, 2), 16))) return false;

  let i = msg.slice(17, 18).readUInt8() + 19;
  const port = msg.slice(i, i += 2).readUInt16BE(0);
  const ATYP = msg.slice(i, i += 1).readUInt8();
  let host;
  if (ATYP === 1) host = msg.slice(i, i += 4).join('.');
  else if (ATYP === 2) host = new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8()));
  else if (ATYP === 3) host = msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':');
  else return false;

  ws.send(new Uint8Array([VERSION, 0]));

  // Check limits before proxying
  if (isLimitExceeded()) {
    ws.close();
    return true;
  }

  const remainingData = msg.slice(i);
  proxyWithCounting(ws, host, port, 'vless', clientIP, remainingData);
  return true;
}

function handleTrojanConnection(ws, msg, clientIP) {
  try {
    if (msg.length < 58) return false;
    const receivedPasswordHash = msg.slice(0, 56).toString();
    const expectedHash = crypto.createHash('sha224').update(UUID).digest('hex');
    if (receivedPasswordHash !== expectedHash) return false;

    let offset = 56;
    if (msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;
    const cmd = msg[offset];
    if (cmd !== 0x01) return false;
    offset += 1;
    const atyp = msg[offset];
    offset += 1;
    let host, port;
    if (atyp === 0x01) {
      host = msg.slice(offset, offset + 4).join('.');
      offset += 4;
    } else if (atyp === 0x03) {
      const hostLen = msg[offset];
      offset += 1;
      host = msg.slice(offset, offset + hostLen).toString();
      offset += hostLen;
    } else if (atyp === 0x04) {
      host = msg.slice(offset, offset + 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':');
      offset += 16;
    } else return false;
    port = msg.readUInt16BE(offset);
    offset += 2;
    if (offset < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;
    const remainingData = msg.slice(offset);

    if (isLimitExceeded()) {
      ws.close();
      return true;
    }

    proxyWithCounting(ws, host, port, 'trojan', clientIP, remainingData);
    return true;
  } catch (error) {
    return false;
  }
}

// ======================== WEBSOCKET PROXY SERVER ========================
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws, req) => {
  const clientIP = req.socket.remoteAddress;
  ws.once('message', msg => {
    if (msg.length > 17 && msg[0] === 0) {
      const id = msg.slice(1, 17);
      const isVless = id.every((v, i) => v == parseInt(uuidBytes.substr(i * 2, 2), 16));
      if (isVless) {
        if (!handleVlessConnection(ws, msg, clientIP)) ws.close();
        return;
      }
    }
    if (!handleTrojanConnection(ws, msg, clientIP)) ws.close();
  }).on('error', () => {});
});

// ======================== ADMIN API & ROUTING ========================
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function isAuthenticated(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
  const token = authHeader.slice(7);
  const expiry = adminTokens.get(token);
  if (!expiry || expiry < Date.now()) return false;
  return true;
}

const httpServer = http.createServer(async (req, res) => {
  const url = req.url;

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // ========== PUBLIC ROUTES ==========
  if (url === '/sub') {
    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const vlessURL = `vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${namePart}`;
    const trojanURL = `trojan://${UUID}@${DOMAIN}:443?security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${namePart}`;
    const subscription = vlessURL + '\n' + trojanURL;
    const base64Content = Buffer.from(subscription).toString('base64');
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(base64Content + '\n');
    return;
  }

  if (url === '/') {
    // Serve admin dashboard HTML (index.html)
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<h1>Hello world! (Admin panel not found)</h1>');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(content);
    });
    return;
  }

  // ========== ADMIN API (protected) ==========
  if (url === '/api/login' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { password } = JSON.parse(body);
        if (password === ADMIN_PASS) {
          const token = generateToken();
          adminTokens.set(token, Date.now() + 24 * 60 * 60 * 1000); // 24h expiry
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, token }));
        } else {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, message: 'Invalid password' }));
        }
      } catch (e) {
        res.writeHead(400);
        res.end();
      }
    });
    return;
  }

  // All other API endpoints require authentication
  if (!isAuthenticated(req)) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }

  // GET /api/stats
  if (url === '/api/stats' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ stats, limits }));
    return;
  }

  // GET /api/logs
  if (url === '/api/logs' && req.method === 'GET') {
    const limit = parseInt(new URL(req.url, `http://${req.headers.host}`).searchParams.get('limit')) || 100;
    const logsToSend = networkLogs.slice(0, limit);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ logs: logsToSend, total: networkLogs.length }));
    return;
  }

  // POST /api/start_recording
  if (url === '/api/start_recording' && req.method === 'POST') {
    recordingEnabled = true;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, recording: recordingEnabled }));
    return;
  }

  // POST /api/stop_recording
  if (url === '/api/stop_recording' && req.method === 'POST') {
    recordingEnabled = false;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, recording: recordingEnabled }));
    return;
  }

  // POST /api/clear_logs
  if (url === '/api/clear_logs' && req.method === 'POST') {
    networkLogs = [];
    saveLogs();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // POST /api/set_limit
  if (url === '/api/set_limit' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { type, value } = JSON.parse(body);
        if (type === 'daily') limits.daily = value;
        else if (type === 'monthly') limits.monthly = value;
        else if (type === 'total') limits.total = value;
        saveLimits();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (e) {
        res.writeHead(400);
        res.end();
      }
    });
    return;
  }

  // 404
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

// Integrate WebSocket upgrade
httpServer.on('upgrade', (req, socket, head) => {
  const url = req.url;
  if (url === `/${WSPATH}`) {
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit('connection', ws, req);
    });
  } else {
    socket.destroy();
  }
});

// ======================== NEZHA AGENT (original) ========================
let ISP = '';
const GetISP = async () => {
  try {
    const res = await axios.get('https://api.ip.sb/geoip');
    const data = res.data;
    ISP = `${data.country_code}-${data.isp}`.replace(/ /g, '_');
  } catch (e) {
    ISP = 'Unknown';
  }
};
GetISP();

const getDownloadUrl = () => {
  const arch = os.arch();
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    return !NEZHA_PORT ? 'https://arm64.ssss.nyc.mn/v1' : 'https://arm64.ssss.nyc.mn/agent';
  } else {
    return !NEZHA_PORT ? 'https://amd64.ssss.nyc.mn/v1' : 'https://amd64.ssss.nyc.mn/agent';
  }
};

const downloadFile = async () => {
  if (!NEZHA_SERVER && !NEZHA_KEY) return;
  const url = getDownloadUrl();
  const response = await axios({ method: 'get', url, responseType: 'stream' });
  const writer = fs.createWriteStream('npm');
  response.data.pipe(writer);
  return new Promise((resolve, reject) => {
    writer.on('finish', () => {
      exec('chmod +x npm', (err) => { if (err) reject(err); else resolve(); });
    });
    writer.on('error', reject);
  });
};

const runnz = async () => {
  try {
    const status = execSync('ps aux | grep -v "grep" | grep "./[n]pm"', { encoding: 'utf-8' });
    if (status.trim() !== '') return;
  } catch (e) {}
  await downloadFile();
  let command = '';
  const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
  if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
    const NEZHA_TLS = tlsPorts.includes(NEZHA_PORT) ? '--tls' : '';
    command = `setsid nohup ./npm -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
  } else if (NEZHA_SERVER && NEZHA_KEY) {
    if (!NEZHA_PORT) {
      const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
      const NZ_TLS = tlsPorts.includes(port) ? 'true' : 'false';
      const configYaml = `client_secret: ${NEZHA_KEY}\ndebug: false\ndisable_auto_update: true\ndisable_command_execute: false\ndisable_force_update: true\ndisable_nat: false\ndisable_send_query: false\ngpu: false\ninsecure_tls: true\nip_report_period: 1800\nreport_delay: 4\nserver: ${NEZHA_SERVER}\nskip_connection_count: true\nskip_procs_count: true\ntemperature: false\ntls: ${NZ_TLS}\nuse_gitee_to_upgrade: false\nuse_ipv6_country_code: false\nuuid: ${UUID}`;
      fs.writeFileSync('config.yaml', configYaml);
    }
    command = `setsid nohup ./npm -c config.yaml >/dev/null 2>&1 &`;
  } else return;
  exec(command, { shell: '/bin/bash' }, (err) => { if (err) console.error(err); });
};

async function addAccessTask() {
  if (!AUTO_ACCESS || !DOMAIN) return;
  try {
    await axios.post("https://oooo.serv00.net/add-url", { url: `https://${DOMAIN}` }, { headers: { 'Content-Type': 'application/json' } });
  } catch (e) {}
}
const delFiles = () => { fs.unlink('npm', () => {}); fs.unlink('config.yaml', () => {}); };

// ======================== INITIALIZATION & START ========================
loadStats();
loadLogs();
loadLimits();
rotateStatsIfNeeded();
setInterval(() => rotateStatsIfNeeded(), 60 * 60 * 1000); // check every hour

httpServer.listen(PORT, () => {
  runnz();
  setTimeout(delFiles, 180000);
  addAccessTask();
  console.log(`Server running on port ${PORT}`);
});
