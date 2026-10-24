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
app.use(express.json({ limit: '14mb' }));
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

let U, M, B = [], rr = 0;   // B = blob collections, one per Mongo cluster
async function putBlob(buf) {
  const id = new ObjectId();
  for (let t = 0; t < B.length; t++) {
    const s = rr++ % B.length; if (!B[s]) continue;
    try { await B[s].insertOne({ _id: id, d: seal(buf), createdAt: new Date() }); return { bs: s, bid: id }; }
    catch (e) { console.error('shard', s + 1, e.message); }
  }
  throw new Error('No storage available');
}

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
  res.json({ id: me.id, username: me.username, about: me.about || '', dpv: me.dpv || 0, contacts });
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
  ct: unseal(m.ct).toString('base64'), media: !!m.bid, r: !!m.r, rx: m.rx || {}, ts: m.createdAt.toISOString() });

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
app.post('/api/messages', auth, async (req, res) => {
  const { to, kind, iv, ct, bIv, blob } = req.body || {};
  if (!['text', 'img', 'vid'].includes(kind) || !iv || !ct || String(ct).length > 40000) return res.status(400).json({ error: 'Bad message' });
  if (!(await U.findOne({ id: String(to) }, { projection: { _id: 1 } }))) return res.status(404).json({ error: 'User not found' });
  const doc = { conv: conv(req.u.id, to), from: req.u.id, to: String(to), kind, iv, ct: seal(Buffer.from(ct, 'base64')), createdAt: new Date() };
  if (kind !== 'text' && blob) Object.assign(doc, await putBlob(Buffer.from(blob, 'base64')), { bIv });
  const [r] = await Promise.all([M.insertOne(doc),
    U.updateOne({ id: req.u.id }, { $addToSet: { contacts: doc.to } }), U.updateOne({ id: doc.to }, { $addToSet: { contacts: req.u.id } })]);
  const m = out({ ...doc, _id: r.insertedId });
  fire([req.u.id, doc.to], 'msg', m.ct.length < 6000 ? m : { id: m.id, from: m.from, to: m.to });   // ciphertext rides inside the event = instant
  res.json(m);
});
app.get('/api/blob/:id', auth, async (req, res) => {
  let m; try { m = await M.findOne({ _id: new ObjectId(req.params.id) }); } catch {}
  if (!m || !m.bid || (m.from !== req.u.id && m.to !== req.u.id)) return res.status(404).end();
  const d = await B[m.bs]?.findOne({ _id: m.bid });
  if (!d) return res.status(404).end();
  res.set({ 'X-IV': m.bIv, 'Content-Type': 'application/octet-stream', 'Cache-Control': 'private, max-age=3600' });
  res.send(unseal(d.d));
});
app.delete('/api/messages/:id', auth, async (req, res) => {
  let m; try { m = await M.findOne({ _id: new ObjectId(req.params.id) }); } catch {}
  if (!m || m.from !== req.u.id) return res.status(403).json({ error: 'Only the sender can delete' });
  await M.deleteOne({ _id: m._id });
  if (m.bid) B[m.bs]?.deleteOne({ _id: m.bid }).catch(() => {});
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

app.post('/api/pusher/auth', auth, (req, res) => {
  const { socket_id, channel_name } = req.body;
  if (channel_name !== chan(req.u.id)) return res.status(403).end();
  res.send(pusher.authorizeChannel(socket_id, channel_name));
});

(async () => {
  const uris = [process.env.MONGODB_URI, ...Array.from({ length: 19 }, (_, i) => process.env['MONGODB_URI_' + (i + 2)])];
  const dbn = process.env.MONGODB_DB || 'lynko';
  const cl = await Promise.all(uris.map((u, i) => !u ? null : MongoClient.connect(u).catch(e => {
    if (!i) throw e; console.error('Skipping MONGODB_URI_' + (i + 1) + ':', e.message); return null; })));
  const dbs = cl.map(c => c && c.db(dbn));
  U = dbs[0].collection('users'); M = dbs[0].collection('messages');
  B = dbs.map(d => d && d.collection('blobs'));
  await U.createIndex({ id: 1 }, { unique: true }); await U.createIndex({ username: 1 }, { unique: true });
  await M.createIndex({ conv: 1, createdAt: 1 }); await M.createIndex({ createdAt: 1 }, { expireAfterSeconds: 86400 });
  await Promise.all(B.filter(Boolean).map(b => b.createIndex({ createdAt: 1 }, { expireAfterSeconds: 86400 })));
  app.listen(process.env.PORT || 3000, () => console.log(`Lynko on :${process.env.PORT || 3000} · ${B.filter(Boolean).length} Mongo cluster(s)`));
})().catch(e => { console.error(e); process.exit(1); });
