require('dotenv').config();
const express = require('express'), crypto = require('crypto'), path = require('path'), compression = require('compression');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), Pusher = require('pusher');
const { MongoClient, ObjectId } = require('mongodb');

const SECRET = process.env.SESSION_SECRET;
const MK = Buffer.from(process.env.MESSAGE_KEY, 'base64');
const pusher = new Pusher({ appId: process.env.PUSHER_APP_ID, key: process.env.PUSHER_KEY,
  secret: process.env.PUSHER_SECRET, cluster: process.env.PUSHER_CLUSTER, useTLS: true });

const app = express();
app.set('trust proxy', 1);
app.use(compression({ filter: (q, r) => !q.path.startsWith('/api/blob') && compression.filter(q, r) }));
app.use(express.json({ limit: '1mb' }));   // media no longer travels as JSON
app.use(express.urlencoded({ extended: false }));

const raw = b => Buffer.isBuffer(b) ? b : Buffer.from(b.buffer.subarray(0, b.length()));
const seal = b => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', MK, iv);
  const e = Buffer.concat([c.update(b), c.final()]); return Buffer.concat([iv, c.getAuthTag(), e]); };
const unseal = bin => { const b = raw(bin); const d = crypto.createDecipheriv('aes-256-gcm', MK, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28)); return Buffer.concat([d.update(b.subarray(28)), d.final()]); };

const tok = req => ((req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith('lynko=')) || '').slice(6);
const auth = (req, res, next) => { try { req.u = jwt.verify(tok(req), SECRET); next(); } catch { res.status(401).json({ error: 'Login required' }); } };
const give = (res, u) => res.cookie('lynko', jwt.sign({ id: u.id, u: u.username }, SECRET, { expiresIn: '30d' }),
  { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 30 * 864e5 });
const tries = new Map();
const limited = ip => { const n = (tries.get(ip) || 0) + 1; tries.set(ip, n); setTimeout(() => tries.delete(ip), 6e5); return n > 15; };
const chan = id => 'private-u-' + id;
const conv = (a, b) => [a, b].sort().join(':');
const fire = (ids, ev, data) => { if (ids.length) pusher.trigger(ids.map(chan), ev, data).catch(() => {}); };
const PUB = { _id: 0, id: 1, username: 1, pub: 1, about: 1, dpv: 1 };

let U, M, S;   // users, messages, statuses  (media is NOT in Mongo any more)

// ── media storage (encrypted files only; see storage.js) ──
const store = require('./storage');
if (!store) console.warn('⚠ No media storage configured: photo/video sending is disabled (set LAKIYA_API_KEY or S3_* — see README)');
const mine = (uid, k) => typeof k === 'string' && k.startsWith(`u/${uid}/`) && /^u\/\d{8}\/[\w-]{6,40}$/.test(k);
const delObj = k => store && store.del(k).catch(() => {});

// async errors -> JSON 500 (never crash)
for (const m of ['get', 'post', 'delete']) { const o = app[m].bind(app);
  app[m] = (p, ...h) => h.length ? o(p, ...h.map(f => f.constructor.name === 'AsyncFunction'
    ? (q, r, n) => f(q, r, n).catch(e => { console.error(e); if (!r.headersSent) r.status(500).json({ error: 'Server error' }); }) : f)) : o(p); }

const page = f => (q, r) => r.sendFile(path.join(__dirname, f));
app.get('/health', (q, r) => r.type('text').send('ok'));   // for UptimeRobot (no DB, no login)
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
  try { await U.insertOne({ id, username: name, hash: await bcrypt.hash(a, 10), pub, encPriv, about: '', dpv: 0, contacts: [], createdAt: new Date() }); }
  catch (e) { return res.status(409).json({ error: 'Username already taken' }); }
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
  const contacts = await U.find({ id: { $in: me.contacts } }, { projection: PUB }).toArray();
  res.json({ id: me.id, username: me.username, pub: me.pub, about: me.about || '', dpv: me.dpv || 0, contacts });
});
app.post('/api/contacts', auth, async (req, res) => {
  const id = String(req.body.id || '').trim();
  const p = await U.findOne({ id }, { projection: PUB });
  if (!p || id === req.u.id) return res.status(404).json({ error: 'No user with that ID' });
  await Promise.all([U.updateOne({ id: req.u.id }, { $addToSet: { contacts: id } }), U.updateOne({ id }, { $addToSet: { contacts: req.u.id } })]);
  res.json(p);
});

// ── profile: DP + about ──
app.post('/api/profile', auth, async (req, res) => {
  const set = {};
  if (typeof req.body.about === 'string') set.about = req.body.about.slice(0, 120);
  if (req.body.dp) {
    if (String(req.body.dp).length > 150000) return res.status(400).json({ error: 'Photo too large' });
    set.dp = Buffer.from(req.body.dp, 'base64'); set.dpv = Date.now();
  }
  await U.updateOne({ id: req.u.id }, { $set: set });
  const u = await U.findOne({ id: req.u.id }, { projection: { contacts: 1, about: 1, dpv: 1 } });
  fire(u.contacts, 'prof', { id: req.u.id });
  res.json({ about: u.about, dpv: u.dpv });
});
app.get('/api/dp/:id', auth, async (req, res) => {
  const u = await U.findOne({ id: req.params.id }, { projection: { dp: 1 } });
  if (!u || !u.dp) return res.status(404).end();
  res.set({ 'Content-Type': 'image/jpeg', 'Cache-Control': 'private, max-age=31536000, immutable' }); res.send(raw(u.dp));
});

// ── messages (server only sees ciphertext) ──
const out = m => ({ id: m._id.toString(), from: m.from, to: m.to, kind: m.kind, iv: m.iv, bIv: m.bIv || null,
  ct: unseal(m.ct).toString('base64'), media: !!m.bkey, r: !!m.r, rx: m.rx || {}, ts: m.createdAt.toISOString() });

app.get('/api/chats', auth, async (req, res) => {   // last message + unread per chat
  const me = await U.findOne({ id: req.u.id }, { projection: { contacts: 1 } });
  const r = await M.aggregate([{ $match: { conv: { $in: me.contacts.map(c => conv(c, req.u.id)) } } }, { $sort: { createdAt: -1 } },
    { $group: { _id: '$conv', last: { $first: '$$ROOT' }, unread: { $sum: { $cond: [{ $and: [{ $eq: ['$to', req.u.id] }, { $ne: ['$r', true] }] }, 1, 0] } } } }]).toArray();
  res.json(r.map(x => ({ peer: x.last.from === req.u.id ? x.last.to : x.last.from, unread: x.unread, last: out(x.last) })));
});
app.get('/api/messages', auth, async (req, res) => {
  const q = { conv: conv(req.u.id, String(req.query.with)) };
  if (req.query.after) q.createdAt = { $gt: new Date(req.query.after) };
  res.json((await M.find(q).sort({ createdAt: 1 }).limit(300).toArray()).map(out));
});
// raw encrypted bytes straight to the bucket (no base64, no Mongo)
app.post('/api/media', auth, express.raw({ type: 'application/octet-stream', limit: '20mb' }), async (req, res) => {
  if (!store) return res.status(503).json({ error: 'Media storage is not configured on the server' });
  if (!Buffer.isBuffer(req.body) || req.body.length < 29) return res.status(400).json({ error: 'Empty file' });
  res.json({ key: await store.put(req.u.id, req.body) });
});
app.post('/api/messages', auth, async (req, res) => {
  const { to, kind, iv, ct, bIv, bkey } = req.body || {};
  if (!['text', 'img', 'vid'].includes(kind) || !iv || !ct || String(ct).length > 40000) return res.status(400).json({ error: 'Bad message' });
  if (!(await U.findOne({ id: String(to) }, { projection: { _id: 1 } }))) return res.status(404).json({ error: 'User not found' });
  const doc = { conv: conv(req.u.id, to), from: req.u.id, to: String(to), kind, iv, ct: seal(Buffer.from(ct, 'base64')), createdAt: new Date() };
  if (kind !== 'text') {
    if (!mine(req.u.id, bkey) || !bIv) return res.status(400).json({ error: 'Missing media' });
    Object.assign(doc, { bkey, bIv: String(bIv) });
  }
  const [r] = await Promise.all([M.insertOne(doc),
    U.updateOne({ id: req.u.id }, { $addToSet: { contacts: doc.to } }), U.updateOne({ id: doc.to }, { $addToSet: { contacts: req.u.id } })]);
  const m = out({ ...doc, _id: r.insertedId });
  fire([req.u.id, doc.to], 'msg', m.ct.length < 6000 ? m : { id: m.id, from: m.from, to: m.to });   // ciphertext rides inside the event = instant
  res.json(m);
});
app.get('/api/blob/:id', auth, async (req, res) => {
  let m; try { m = await M.findOne({ _id: new ObjectId(req.params.id) }); } catch {}
  if (!m || !m.bkey || !store || (m.from !== req.u.id && m.to !== req.u.id)) return res.status(404).end();
  await store.send(m.bkey, res, { 'X-IV': m.bIv, 'Cache-Control': 'private, max-age=3600' });
});
app.delete('/api/messages/:id', auth, async (req, res) => {
  let m; try { m = await M.findOne({ _id: new ObjectId(req.params.id) }); } catch {}
  if (!m || m.from !== req.u.id) return res.status(403).json({ error: 'Only the sender can delete' });
  await M.deleteOne({ _id: m._id });
  if (m.bkey) delObj(m.bkey);
  fire([m.from, m.to], 'del', { id: req.params.id });
  res.json({ ok: 1 });
});
app.post('/api/read', auth, async (req, res) => {
  const w = String(req.body.with);
  const r = await M.updateMany({ conv: conv(req.u.id, w), to: req.u.id, r: { $ne: true } }, { $set: { r: true } });
  if (r.modifiedCount) fire([w], 'read', { by: req.u.id });
  res.json({ ok: 1 });
});
app.post('/api/typing', auth, (req, res) => { fire([String(req.body.to)], 'typing', { from: req.u.id }); res.status(204).end(); });
const EMO = ['❤️', '😍', '🥰', '😘', '😂', '😢', '🔥', '👍'];
app.post('/api/react', auth, async (req, res) => {
  let m; try { m = await M.findOne({ _id: new ObjectId(req.body.id) }); } catch {}
  if (!m || (m.from !== req.u.id && m.to !== req.u.id) || !EMO.includes(req.body.e)) return res.status(400).json({ error: 'Bad reaction' });
  const k = 'rx.' + req.u.id, same = m.rx && m.rx[req.u.id] === req.body.e;
  const n = await M.findOneAndUpdate({ _id: m._id }, same ? { $unset: { [k]: 1 } } : { $set: { [k]: req.body.e } }, { returnDocument: 'after' });
  const rx = (n && n.rx) || (n && n.value && n.value.rx) || {};
  fire([m.from, m.to], 'rx', { id: req.body.id, rx, by: req.u.id });
  res.json({ rx });
});

// ── status (24h, end-to-end encrypted: one random key per status, wrapped for every contact) ──
const sOut = (s, uid) => ({ id: s._id.toString(), from: s.from, ts: s.createdAt.toISOString(), iv: s.iv, ct: unseal(s.ct).toString('base64'),
  wk: (s.keys || {})[uid] || null, media: !!s.bkey, bIv: s.bIv || null, seen: !!(s.views || {})[uid],
  ...(s.from === uid ? { views: Object.entries(s.views || {}).map(([id, t]) => ({ id, ts: new Date(t).toISOString() })) } : {}) });
const sGet = async id => { try { return await S.findOne({ _id: new ObjectId(id) }); } catch { return null; } };

app.post('/api/status', auth, async (req, res) => {
  const { iv, ct, keys, bkey, bIv } = req.body || {};
  if (!iv || !ct || String(ct).length > 20000 || !keys || typeof keys !== 'object') return res.status(400).json({ error: 'Bad status' });
  const me = await U.findOne({ id: req.u.id }, { projection: { contacts: 1 } });
  const wk = {};
  for (const id of [...me.contacts, req.u.id]) { const w = keys[id];
    if (w && typeof w.iv === 'string' && typeof w.ct === 'string' && w.ct.length < 400) wk[id] = { iv: w.iv, ct: w.ct }; }
  if (!wk[req.u.id]) return res.status(400).json({ error: 'Bad status' });
  if (await S.countDocuments({ from: req.u.id }) >= 30) return res.status(400).json({ error: 'Too many active statuses (max 30)' });
  const doc = { from: req.u.id, createdAt: new Date(), iv: String(iv), ct: seal(Buffer.from(ct, 'base64')), keys: wk, views: {} };
  if (bkey) { if (!mine(req.u.id, bkey) || !bIv) return res.status(400).json({ error: 'Missing media' }); Object.assign(doc, { bkey, bIv: String(bIv) }); }
  const r = await S.insertOne(doc);
  fire(Object.keys(wk), 'status', { from: req.u.id });
  res.json(sOut({ ...doc, _id: r.insertedId }, req.u.id));
});
app.get('/api/statuses', auth, async (req, res) => {
  const me = await U.findOne({ id: req.u.id }, { projection: { contacts: 1 } });
  const q = { createdAt: { $gt: new Date(Date.now() - 864e5) },
    $or: [{ from: req.u.id }, { from: { $in: me.contacts }, ['keys.' + req.u.id]: { $exists: true } }] };
  res.json((await S.find(q).sort({ createdAt: 1 }).limit(300).toArray()).map(s => sOut(s, req.u.id)));
});
app.post('/api/status/:id/view', auth, async (req, res) => {
  const s = await sGet(req.params.id);
  if (!s || s.from === req.u.id || !(s.keys || {})[req.u.id]) return res.status(404).end();
  const r = await S.updateOne({ _id: s._id, ['views.' + req.u.id]: { $exists: false } }, { $set: { ['views.' + req.u.id]: new Date() } });
  if (r.modifiedCount) fire([s.from], 'sview', { id: req.params.id, by: req.u.id });
  res.json({ ok: 1 });
});
app.get('/api/status/:id/blob', auth, async (req, res) => {
  const s = await sGet(req.params.id);
  if (!s || !s.bkey || !store || (s.from !== req.u.id && !(s.keys || {})[req.u.id])) return res.status(404).end();
  await store.send(s.bkey, res, { 'Cache-Control': 'private, max-age=3600' });
});
app.delete('/api/status/:id', auth, async (req, res) => {
  const s = await sGet(req.params.id);
  if (!s || s.from !== req.u.id) return res.status(403).json({ error: 'Only the owner can delete' });
  await S.deleteOne({ _id: s._id }); if (s.bkey) delObj(s.bkey);
  fire(Object.keys(s.keys || {}), 'sdel', { id: req.params.id });
  res.json({ ok: 1 });
});

app.post('/api/pusher/auth', auth, (req, res) => {
  const { socket_id, channel_name } = req.body;
  if (channel_name !== chan(req.u.id)) return res.status(403).end();
  res.send(pusher.authorizeChannel(socket_id, channel_name));
});

app.use((e, q, r, n) => r.status(e.status || 500).json({ error: e.type === 'entity.too.large' ? 'File too large' : 'Server error' }));

(async () => {
  const cl = await MongoClient.connect(process.env.MONGODB_URI);
  const db = cl.db(process.env.MONGODB_DB || 'lynko');
  U = db.collection('users'); M = db.collection('messages'); S = db.collection('statuses');
  await U.createIndex({ id: 1 }, { unique: true }); await U.createIndex({ username: 1 }, { unique: true });
  await M.createIndex({ conv: 1, createdAt: 1 }); await M.createIndex({ createdAt: 1 }, { expireAfterSeconds: 86400 });
  await S.createIndex({ from: 1, createdAt: -1 }); await S.createIndex({ createdAt: 1 }, { expireAfterSeconds: 86400 });
  app.listen(process.env.PORT || 3000, () => console.log(`Lynko on :${process.env.PORT || 3000} · media: ${store ? store.name : 'DISABLED'}`));
  if (store) { store.sweep(); setInterval(store.sweep, 36e5); }
})().catch(e => { console.error(e); process.exit(1); });
