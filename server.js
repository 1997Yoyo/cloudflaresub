import express from 'express';
import { randomBytes, createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, 'data');
const PUBLIC_DIR = join(__dirname, 'public');

if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });

const TTL_MS = 7 * 24 * 60 * 60 * 1000;

function kvGet(key) {
  const filePath = join(DATA_DIR, key.replace(/[^a-zA-Z0-9_-]/g, '_'));
  if (!existsSync(filePath)) return null;
  const raw = readFileSync(filePath, 'utf-8');
  const entry = JSON.parse(raw);
  if (Date.now() - entry.createdAt > TTL_MS) { unlinkSync(filePath); return null; }
  return entry.value;
}

function kvPut(key, value) {
  const filePath = join(DATA_DIR, key.replace(/[^a-zA-Z0-9_-]/g, '_'));
  writeFileSync(filePath, JSON.stringify({ createdAt: Date.now(), value }));
}

function escapeYaml(str = '') {
  return String(str).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, ' ');
}

function parsePreferredEndpoints(input) {
  return String(input || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean).map(line => {
    const [raw, remark = ''] = line.split('#');
    const value = raw.trim();
    const match = value.match(/^(.*?)(?::(\d+))?$/);
    return { server: match?.[1] || value, port: match?.[2] ? Number(match[2]) : undefined, remark: remark.trim() };
  });
}

function parseVmess(link) {
  const raw = link.slice('vmess://'.length).trim();
  const obj = JSON.parse(Buffer.from(raw, 'base64').toString());
  return { type: 'vmess', name: obj.ps || 'vmess', server: obj.add, port: Number(obj.port || 443), uuid: obj.id, cipher: obj.scy || 'auto', network: obj.net || 'ws', tls: obj.tls === 'tls', host: obj.host || '', path: obj.path || '/', sni: obj.sni || obj.host || '', alpn: obj.alpn || '', fp: obj.fp || '' };
}

function parseUrlLike(link, type) {
  const u = new URL(link);
  return { type, name: decodeURIComponent(u.hash.replace(/^#/, '')) || type, server: u.hostname, port: Number(u.port || 443), password: type === 'trojan' ? decodeURIComponent(u.username) : undefined, uuid: type === 'vless' ? decodeURIComponent(u.username) : undefined, network: u.searchParams.get('type') || 'tcp', tls: (u.searchParams.get('security') || '').toLowerCase() === 'tls', host: u.searchParams.get('host') || u.searchParams.get('sni') || '', path: u.searchParams.get('path') || '/', sni: u.searchParams.get('sni') || u.searchParams.get('host') || '', fp: u.searchParams.get('fp') || '', alpn: u.searchParams.get('alpn') || '', flow: u.searchParams.get('flow') || '' };
}

function parseRawLinks(input) {
  const lines = String(input || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const result = [];
  for (const line of lines) {
    if (line.startsWith('vmess://')) { result.push(parseVmess(line)); continue; }
    if (line.startsWith('vless://')) { result.push(parseUrlLike(line, 'vless')); continue; }
    if (line.startsWith('trojan://')) { result.push(parseUrlLike(line, 'trojan')); continue; }
    try { const decoded = Buffer.from(line, 'base64').toString(); if (/^(vmess|vless|trojan):\/\//m.test(decoded)) result.push(...parseRawLinks(decoded)); } catch {}
  }
  return result;
}

function buildNodes(baseNodes, preferredEndpoints, options = {}) {
  const output = [];
  const prefix = (options.namePrefix || '').trim();
  let counter = 0;
  for (const node of baseNodes) {
    for (const ep of preferredEndpoints) {
      counter += 1;
      const nameParts = [];
      if (node.name) nameParts.push(node.name);
      if (prefix) nameParts.push(prefix);
      if (ep.remark) nameParts.push(ep.remark); else nameParts.push(String(counter));
      output.push({ ...node, name: nameParts.join(' | '), server: ep.server, port: ep.port || node.port, host: options.keepOriginalHost ? node.host : '', sni: options.keepOriginalHost ? node.sni : '' });
    }
  }
  return output;
}

function encodeVmess(node) {
  return 'vmess://' + Buffer.from(JSON.stringify({ v: '2', ps: node.name, add: node.server, port: String(node.port), id: node.uuid, aid: '0', scy: node.cipher || 'auto', net: node.network || 'ws', type: 'none', host: node.host || '', path: node.path || '/', tls: node.tls ? 'tls' : '', sni: node.sni || '', alpn: node.alpn || '', fp: node.fp || '' })).toString('base64');
}

function encodeVless(node) {
  const url = new URL(`vless://${encodeURIComponent(node.uuid)}@${node.server}:${node.port}`);
  url.searchParams.set('type', node.network || 'ws');
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  if (node.flow) url.searchParams.set('flow', node.flow);
  url.hash = node.name;
  return url.toString();
}

function encodeTrojan(node) {
  const url = new URL(`trojan://${encodeURIComponent(node.password)}@${node.server}:${node.port}`);
  if (node.network) url.searchParams.set('type', node.network);
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  url.hash = node.name;
  return url.toString();
}

function renderRaw(nodes) {
  return Buffer.from(nodes.map(n => { if (n.type === 'vmess') return encodeVmess(n); if (n.type === 'vless') return encodeVless(n); if (n.type === 'trojan') return encodeTrojan(n); return ''; }).filter(Boolean).join('\n')).toString('base64');
}

function renderProxyList(nodes) {
  return nodes.map(node => {
    if (node.type === 'vmess') {
      const lines = [`  - name: "${escapeYaml(node.name)}"`, `    type: vmess`, `    server: ${node.server}`, `    port: ${node.port}`, `    uuid: ${node.uuid}`, `    alterId: 0`, `    cipher: ${node.cipher || 'auto'}`, `    udp: true`, `    tls: ${node.tls ? 'true' : 'false'}`, `    network: ${node.network || 'ws'}`];
      if (node.sni) lines.push(`    servername: "${escapeYaml(node.sni)}"`);
      if ((node.network || 'ws') === 'ws') lines.push(`    ws-opts:`, `      path: "${escapeYaml(node.path || '/')}"`, `      headers:`, `        Host: "${escapeYaml(node.host || node.sni || '')}"`);
      return lines.join('\n');
    }
    if (node.type === 'vless') {
      const lines = [`  - name: "${escapeYaml(node.name)}"`, `    type: vless`, `    server: ${node.server}`, `    port: ${node.port}`, `    uuid: ${node.uuid}`, `    udp: true`, `    tls: ${node.tls ? 'true' : 'false'}`, `    network: ${node.network || 'ws'}`];
      if (node.sni) lines.push(`    servername: "${escapeYaml(node.sni)}"`);
      if ((node.network || 'ws') === 'ws') lines.push(`    ws-opts:`, `      path: "${escapeYaml(node.path || '/')}"`, `      headers:`, `        Host: "${escapeYaml(node.host || node.sni || '')}"`);
      return lines.join('\n');
    }
    if (node.type === 'trojan') {
      const lines = [`  - name: "${escapeYaml(node.name)}"`, `    type: trojan`, `    server: ${node.server}`, `    port: ${node.port}`, `    password: "${escapeYaml(node.password || '')}"`, `    udp: true`];
      if (node.sni) lines.push(`    sni: "${escapeYaml(node.sni)}"`);
      if (node.tls !== false) lines.push(`    tls: true`);
      if (node.network) lines.push(`    network: ${node.network}`);
      if (node.network === 'ws') lines.push(`    ws-opts:`, `      path: "${escapeYaml(node.path || '/')}"`, `      headers:`, `        Host: "${escapeYaml(node.host || node.sni || '')}"`);
      return lines.join('\n');
    }
    return '';
  }).filter(Boolean);
}

function parseCustomRuleGroups(ruleLines) {
  const groups = new Set();
  for (const line of ruleLines) {
    const parts = line.split(',');
    if (parts.length >= 3) { const g = parts[parts.length - 1].trim(); if (g && g !== 'DIRECT' && g !== 'REJECT' && g !== 'PASS') groups.add(g); }
  }
  return groups;
}

function renderClash(nodes, customRules) {
  const proxies = renderProxyList(nodes);
  const proxyNamesYaml = nodes.map(n => `      - "${escapeYaml(n.name)}"`);
  let ruleLines = [], extraGroups = [];
  if (customRules && typeof customRules === 'string' && customRules.trim()) {
    ruleLines = customRules.split('\n').map(l => l.trim()).filter(Boolean);
    for (const name of parseCustomRuleGroups(ruleLines)) {
      if (name === '\u{1F680} \u8282\u70B9\u9009\u62E9') continue;
      extraGroups.push(`  - name: "${escapeYaml(name)}"`, `    type: select`, `    proxies:`, `      - "\u{1F680} \u8282\u70B9\u9009\u62E9"`, `      - DIRECT`, ``);
    }
  }
  return [`mixed-port: 7890`, `allow-lan: false`, `mode: rule`, `log-level: info`, `ipv6: true`, ``, `proxies:`, ...(proxies.length ? proxies : []), ``, `proxy-groups:`, `  - name: "\u267B\uFE0F \u81EA\u52A8\u9009\u62E9"`, `    type: url-test`, `    url: "http://www.gstatic.com/generate_204"`, `    interval: 300`, `    tolerance: 50`, `    proxies:`, ...proxyNamesYaml, ``, `  - name: "\u{1F680} \u8282\u70B9\u9009\u62E9"`, `    type: select`, `    proxies:`, `      - "\u267B\uFE0F \u81EA\u52A8\u9009\u62E9"`, ...proxyNamesYaml, `      - DIRECT`, ``, ...extraGroups, `rules:`, ...(ruleLines.length ? ruleLines.map(r => `  - ${r.startsWith('- ') ? r.slice(2) : r}`) : [`  - MATCH,\u{1F680} \u8282\u70B9\u9009\u62E9`])].join('\n');
}

function renderSurge(nodes) {
  const proxies = nodes.filter(n => n.type === 'vmess' || n.type === 'trojan').map(n => n.type === 'vmess' ? `${n.name} = vmess, ${n.server}, ${n.port}, username=${n.uuid}, ws=true, ws-path=${n.path || '/'}, ws-headers=Host:${n.host || ''}, tls=${n.tls ? 'true' : 'false'}, sni=${n.sni || ''}` : `${n.name} = trojan, ${n.server}, ${n.port}, password=${n.password || ''}, sni=${n.sni || ''}`);
  return ['[General]', 'skip-proxy = 127.0.0.1, localhost', '', '[Proxy]', ...proxies, '', '[Proxy Group]', 'Proxy = select, ' + nodes.filter(n => n.type === 'vmess' || n.type === 'trojan').map(n => n.name).join(', '), '', '[Rule]', 'FINAL,Proxy', ''].join('\n');
}

function createShortId(length = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  return Array.from(randomBytes(length)).map(b => chars[b % chars.length]).join('');
}

function normalizeLines(v) { return String(v || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean).sort().join('\n'); }
function sha256Hex(i) { return createHash('sha256').update(i).digest('hex'); }
function buildDedupHash(b) { return sha256Hex(JSON.stringify({ nodeLinks: normalizeLines(b.nodeLinks), preferredIps: normalizeLines(b.preferredIps), namePrefix: String(b.namePrefix || '').trim(), keepOriginalHost: b.keepOriginalHost !== false, customRules: normalizeLines(b.customRules) })); }

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

app.post('/api/generate', (req, res) => {
  try {
    const body = req.body;
    const baseNodes = parseRawLinks(body.nodeLinks || '');
    const preferredEndpoints = parsePreferredEndpoints(body.preferredIps || '');
    if (!baseNodes.length) return res.status(400).json({ ok: false, error: '没有识别到可用节点' });
    if (!preferredEndpoints.length) return res.status(400).json({ ok: false, error: '没有识别到可用优选地址' });
    const nodes = buildNodes(baseNodes, preferredEndpoints, { namePrefix: body.namePrefix || '', keepOriginalHost: body.keepOriginalHost !== false });
    const customRules = body.customRules || '';
    const dedupHash = buildDedupHash(body);
    let id = kvGet('dedup:' + dedupHash);
    if (!id) { id = createShortId(); kvPut('sub:' + id, { version: 3, createdAt: new Date().toISOString(), nodes, ...(customRules.trim() ? { customRules } : {}) }); kvPut('dedup:' + dedupHash, id); }
    const origin = `${req.protocol}://${req.get('host')}`;
    res.json({ ok: true, storage: 'file', deduplicated: true, shortId: id, urls: { auto: origin + '/sub/' + id, raw: origin + '/sub/' + id + '?target=raw', clash: origin + '/sub/' + id + '?target=clash', surge: origin + '/sub/' + id + '?target=surge' }, counts: { inputNodes: baseNodes.length, preferredEndpoints: preferredEndpoints.length, outputNodes: nodes.length }, preview: nodes.slice(0, 20).map(n => ({ name: n.name, type: n.type, server: n.server, port: n.port, host: n.host || '', sni: n.sni || '' })) });
  } catch (err) { res.status(500).json({ ok: false, error: err.message }); }
});

app.get('/sub/:id', (req, res) => {
  try {
    const raw = kvGet('sub:' + req.params.id);
    if (!raw) return res.status(404).send('not found');
    const target = (req.query.target || 'raw').toLowerCase();
    res.set('Content-Type', target === 'clash' ? 'text/yaml; charset=utf-8' : 'text/plain; charset=utf-8');
    if (target === 'clash') res.send(renderClash(raw.nodes || [], raw.customRules || ''));
    else if (target === 'surge') res.send(renderSurge(raw.nodes || []));
    else res.send(renderRaw(raw.nodes || []));
  } catch (err) { res.status(500).send(err.message); }
});

app.get('*', (req, res) => res.sendFile(join(PUBLIC_DIR, 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`CloudflareSub Server running on http://0.0.0.0:${PORT}`));
