require('dotenv').config();
const express = require('express'), crypto = require('crypto'), path = require('path');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), Pusher = require('pusher');
const { MongoClient, ObjectId } = require('mongodb');

const SECRET = process.env.SESSION_SECRET;
const MK = Buffer.from(process.env.MESSAGE_KEY, 'base64');       // at-rest layer (server side)
const pusher = new Pusher({ appId: process.env.PUSHER_APP_ID, key: process.env.PUSHER_KEY,
  secret: process.env.PUSHER_SECRET, cluster: process.env.PUSHER_CLUSTER, useTLS: true });

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '14mb' }));
app.use(express.urlencoded({ extended: false }));

// ── at-rest sealing: iv(12) | tag(16) | data ──
const seal = b => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', MK, iv);
  const e = Buffer.concat([c.update(b), c.final()]); return Buffer.concat([iv, c.getAuthTag(), e]); };
const unseal = bin => { const b = Buffer.from(bin.buffer.subarray(0, bin.length()));
  const d = crypto.createDecipheriv('aes-256-gcm', MK, b.subarray(0, 12)); d.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([d.update(b.subarray(28)), d.final()]); };

// ── auth helpers ──
const tok = req => ((req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith('lynko=')) || '').slice(6);
const auth = (req, res, next) => { try { req.u = jwt.verify(tok(req), SECRET); next(); } catch { res.status(401).json({ error: 'Login required' }); } };
const give = (res, u) => res.cookie('lynko', jwt.sign({ id: u.id, u: u.username }, SECRET, { expiresIn: '30d' }),
  { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 30 * 864e5 });
const tries = new Map();
const limited = ip => { const n = (tries.get(ip) || 0) + 1; tries.set(ip, n); setTimeout(() => tries.delete(ip), 6e5); return n > 15; };
const chan = id => 'private-u-' + id;
const conv = (a, b) => [a, b].sort().join(':');
const fire = (ids, ev, data) => pusher.trigger(ids.map(chan), ev, data).catch(() => {});

let U, M;

// ── pages (no static folder, so .env is never exposed) ──
const page = f => (q, r) => r.sendFile(path.join(__dirname, f));
app.get('/', page('index.html'));
app.get('/chat', page('chat.html'));
app.get('/api/config', (q, r) => r.json({ key: process.env.PUSHER_KEY, cluster: process.env.PUSHER_CLUSTER }));

// ── accounts ──
app.post('/api/register', async (req, res) => {
  const { username, auth: a, pub, encPriv } = req.body || {};
  const name = String(username || '').toLowerCase();
  if (!/^[a-z0-9_]{3,20}$/.test(name)) return res.status(400).json({ error: 'Username: 3-20 letters, numbers or _' });
  if (!/^[0-9a-f]{64}$/.test(a || '') || !pub || !encPriv) return res.status(400).json({ error: 'Bad request' });
  if (limited(req.ip)) return res.status(429).json({ error: 'Too many tries. Wait a few minutes.' });
  let id; do { id = String(crypto.randomInt(10000000, 99999999)); } while (await U.findOne({ id }));
  try {
    await U.insertOne({ id, username: name, hash: await bcrypt.hash(a, 10), pub, encPriv, contacts: [], createdAt: new Date() });
  } catch (e) { return res.status(409).json({ error: 'Username already taken' }); }
  give(res, { id, username: name }); res.json({ id, username: name });
});
app.post('/api/login', async (req, res) => {
  if (limited(req.ip)) return res.status(429).json({ error: 'Too many tries. Wait a few minutes.' });
  const u = await U.findOne({ username: String(req.body.username || '').toLowerCase() });
  if (!u || !(await bcrypt.compare(String(req.body.auth || ''), u.hash))) return res.status(401).json({ error: 'Wrong username or password' });
  give(res, u); res.json({ id: u.id, username: u.username, pub: u.pub, encPriv: u.encPriv });
});
app.post('/api/logout', (q, r) => { r.clearCookie('lynko'); r.json({ ok: 1 }); });

app.get('/api/me', auth, async (req, res) => {
  const me = await U.findOne({ id: req.u.id });
  if (!me) return res.status(401).json({ error: 'Login required' });
  const contacts = await U.find({ id: { $in: me.contacts } }, { projection: { _id: 0, id: 1, username: 1, pub: 1 } }).toArray();
  res.json({ id: me.id, username: me.username, contacts });
});
app.post('/api/contacts', auth, async (req, res) => {
  const id = String(req.body.id || '').trim();
  const p = await U.findOne({ id }, { projection: { _id: 0, id: 1, username: 1, pub: 1 } });
  if (!p || id === req.u.id) return res.status(404).json({ error: 'No user with that ID' });
  await U.updateOne({ id: req.u.id }, { $addToSet: { contacts: id } });
  await U.updateOne({ id }, { $addToSet: { contacts: req.u.id } });
  res.json(p);
});

// ── messages (server only ever sees ciphertext) ──
const out = m => ({ id: m._id.toString(), from: m.from, to: m.to, kind: m.kind, iv: m.iv, bIv: m.bIv || null,
  ct: unseal(m.ct).toString('base64'), media: !!m.blob, ts: m.createdAt.toISOString() });

app.get('/api/messages', auth, async (req, res) => {
  const q = { conv: conv(req.u.id, String(req.query.with)) };
  if (req.query.after) q.createdAt = { $gt: new Date(req.query.after) };
  const list = await M.find(q, { projection: { blob: 0 } }).sort({ createdAt: 1 }).limit(300).toArray();
  res.json(list.map(out));
});
app.post('/api/messages', auth, async (req, res) => {
  const { to, kind, iv, ct, bIv, blob } = req.body || {};
  if (!['text', 'img', 'vid'].includes(kind) || !iv || !ct || String(ct).length > 40000) return res.status(400).json({ error: 'Bad message' });
  if (!(await U.findOne({ id: String(to) }, { projection: { _id: 1 } }))) return res.status(404).json({ error: 'User not found' });
  const doc = { conv: conv(req.u.id, to), from: req.u.id, to: String(to), kind, iv, ct: seal(Buffer.from(ct, 'base64')), createdAt: new Date() };
  if (kind !== 'text' && blob) { doc.blob = seal(Buffer.from(blob, 'base64')); doc.bIv = bIv; }
  const r = await M.insertOne(doc);
  await U.updateOne({ id: req.u.id }, { $addToSet: { contacts: doc.to } });
  await U.updateOne({ id: doc.to }, { $addToSet: { contacts: req.u.id } });
  fire([req.u.id, doc.to], 'msg', { id: r.insertedId.toString(), from: req.u.id, to: doc.to });
  res.json(out({ ...doc, _id: r.insertedId }));
});
app.get('/api/blob/:id', auth, async (req, res) => {
  let m; try { m = await M.findOne({ _id: new ObjectId(req.params.id) }); } catch {}
  if (!m || !m.blob || (m.from !== req.u.id && m.to !== req.u.id)) return res.status(404).end();
  res.set({ 'X-IV': m.bIv, 'Content-Type': 'application/octet-stream', 'Cache-Control': 'private, max-age=3600' });
  res.send(unseal(m.blob));
});
app.delete('/api/messages/:id', auth, async (req, res) => {
  let m; try { m = await M.findOne({ _id: new ObjectId(req.params.id) }, { projection: { from: 1, to: 1 } }); } catch {}
  if (!m || m.from !== req.u.id) return res.status(403).json({ error: 'Only the sender can delete' });
  await M.deleteOne({ _id: m._id });
  fire([m.from, m.to], 'del', { id: req.params.id });
  res.json({ ok: 1 });
});

// ── pusher private channel auth ──
app.post('/api/pusher/auth', auth, (req, res) => {
  const { socket_id, channel_name } = req.body;
  if (channel_name !== chan(req.u.id)) return res.status(403).end();
  res.send(pusher.authorizeChannel(socket_id, channel_name));
});

(async () => {
  const c = await MongoClient.connect(process.env.MONGODB_URI);
  const db = c.db(process.env.MONGODB_DB || 'lynko');
  U = db.collection('users'); M = db.collection('messages');
  await U.createIndex({ id: 1 }, { unique: true });
  await U.createIndex({ username: 1 }, { unique: true });
  await M.createIndex({ conv: 1, createdAt: 1 });
  await M.createIndex({ createdAt: 1 }, { expireAfterSeconds: 86400 }); // everything auto-deletes after 24h
  app.listen(process.env.PORT || 3000, () => console.log('Lynko running on :' + (process.env.PORT || 3000)));
})().catch(e => { console.error(e); process.exit(1); });
