// Media storage for ENCRYPTED files (the server never sees photos/videos in clear).
// Pick one with env vars:
//   LAKIYA_API_KEY=...            -> Lakiya Cloud  (https://cloud.laksidu.site, no credit card)
//   S3_BUCKET=... (+S3_*)         -> any S3 bucket (Cloudflare R2, Backblaze B2, ...)
const { Readable } = require('stream');
const crypto = require('crypto');

function make() {
  // ───────── Lakiya Cloud ─────────
  if (process.env.LAKIYA_API_KEY || process.env.STORAGE === 'lakiya') {
    const base = (process.env.LAKIYA_URL || 'https://cloud.laksidu.site').replace(/\/$/, '');
    const apiKey = process.env.LAKIYA_API_KEY || '';
    const expiry = process.env.LAKIYA_EXPIRY || '24h';          // 1h, 6h, 24h, 7d, 30d (0 = permanent)
    return {
      name: 'Lakiya Cloud (' + base + ')',
      async put(uid, buf) {
        const fd = new FormData();
        fd.append('file', new Blob([buf], { type: 'application/octet-stream' }), crypto.randomBytes(8).toString('hex') + '.bin');
        fd.append('expiry', expiry);
        const r = await fetch(base + '/api/cloud/upload', { method: 'POST', headers: apiKey ? { 'x-api-key': apiKey } : {}, body: fd });
        const j = await r.json().catch(() => ({}));
        if (!r.ok || !j.file_id) throw new Error('Lakiya upload failed: ' + (j.error || j.message || r.status));
        return `u/${uid}/${j.file_id}`;
      },
      async send(key, res, extra = {}) {
        try {
          const r = await fetch(base + '/dl/' + encodeURIComponent(key.split('/')[2]));
          if (!r.ok || !r.body) return res.status(404).end();
          res.set({ ...extra, 'Content-Type': 'application/octet-stream' });
          const len = r.headers.get('content-length'); if (len) res.set('Content-Length', len);
          const s = Readable.fromWeb(r.body); s.on('error', () => res.destroy()); s.pipe(res);
        } catch { if (!res.headersSent) res.status(404).end(); }
      },
      async del() {},     // files expire by themselves (LAKIYA_EXPIRY)
      async sweep() {},
    };
  }
  // ───────── S3-compatible (R2 / B2 / ...) ─────────
  if (process.env.S3_BUCKET) {
    const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');
    const Bucket = process.env.S3_BUCKET;
    const s3 = new S3Client({ region: process.env.S3_REGION || 'auto', endpoint: process.env.S3_ENDPOINT, forcePathStyle: true,
      credentials: { accessKeyId: process.env.S3_ACCESS_KEY, secretAccessKey: process.env.S3_SECRET_KEY },
      requestChecksumCalculation: 'WHEN_REQUIRED', responseChecksumValidation: 'WHEN_REQUIRED' });
    const del = Key => s3.send(new DeleteObjectCommand({ Bucket, Key })).catch(() => {});
    return {
      name: 'bucket ' + Bucket,
      async put(uid, buf) { const Key = `u/${uid}/${crypto.randomBytes(12).toString('hex')}`;
        await s3.send(new PutObjectCommand({ Bucket, Key, Body: buf, ContentType: 'application/octet-stream' })); return Key; },
      async send(Key, res, extra = {}) {
        try {
          const r = await s3.send(new GetObjectCommand({ Bucket, Key }));
          res.set({ ...extra, 'Content-Type': 'application/octet-stream' });
          if (r.ContentLength) res.set('Content-Length', String(r.ContentLength));
          r.Body.on('error', () => res.destroy()); r.Body.pipe(res);
        } catch { if (!res.headersSent) res.status(404).end(); }
      },
      del,
      async sweep() {
        try {
          let t, n = 0; const old = Date.now() - 26 * 36e5;
          do {
            const r = await s3.send(new ListObjectsV2Command({ Bucket, Prefix: 'u/', ContinuationToken: t }));
            for (const o of r.Contents || []) if (o.LastModified.getTime() < old) { await del(o.Key); n++; }
            t = r.IsTruncated ? r.NextContinuationToken : undefined;
          } while (t);
          if (n) console.log('sweep: removed', n, 'expired file(s)');
        } catch (e) { console.error('sweep', e.message); }
      },
    };
  }
  return null;
}
module.exports = make();
