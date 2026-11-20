import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const ADMIN_AUTH_FILE = path.resolve(process.cwd(), '.admin-auth.json');
const ALERT_OUTBOX_FILE = path.resolve(process.cwd(), '.stock-alert-outbox.json');
const FIREBASE_CONFIG_FILE = path.resolve(process.cwd(), 'firebase-applet-config.json');
const BOOTSTRAP_ADMIN_EMAIL = 'sohel901190@gmail.com';
const SESSION_SECRET = process.env.ADMIN_SESSION_SECRET || crypto.createHash('sha256').update(process.env.APP_URL || 'ms-fashion-secret-key').digest('hex');

const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const attemptStore = new Map<string, { count: number; lockedUntil: number }>();

function getFirebaseApiKey(): string {
  try {
    if (fs.existsSync(FIREBASE_CONFIG_FILE)) {
      const cfg = JSON.parse(fs.readFileSync(FIREBASE_CONFIG_FILE, 'utf8'));
      return String(cfg?.apiKey || '');
    }
  } catch {
    // ignore
  }
  return '';
}

async function verifyAdminRequest(req: express.Request): Promise<boolean> {
  const token = String(req.body?.sessionToken || req.headers['x-admin-session'] || '');
  const decoded = verifySessionToken(token);
  if (decoded && decoded.role === 'admin') return true;

  const authHeader = String(req.headers.authorization || '');
  const idToken = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : String(req.body?.firebaseIdToken || '').trim();
  const apiKey = getFirebaseApiKey();
  if (!idToken || !apiKey) return false;

  try {
    const resp = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(apiKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken }),
    });
    if (!resp.ok) return false;
    const data = (await resp.json()) as { users?: Array<{ email?: string; emailVerified?: boolean }> };
    const u = data?.users?.[0];
    return Boolean(u && String(u.email || '').toLowerCase() === BOOTSTRAP_ADMIN_EMAIL && u.emailVerified);
  } catch {
    return false;
  }
}

function hashPassword(password: string, salt?: string): string {
  const usedSalt = salt || crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, usedSalt, 64).toString('hex');
  return `${usedSalt}:${derived}`;
}

function verifyPasswordHash(password: string, storedHash: string): boolean {
  const parts = String(storedHash || '').split(':');
  if (parts.length !== 2) return false;
  const [salt, keyHex] = parts;
  const derived = crypto.scryptSync(password, salt, 64);
  const keyBuf = Buffer.from(keyHex, 'hex');
  if (derived.length !== keyBuf.length) return false;
  return crypto.timingSafeEqual(derived, keyBuf);
}

function getStoredAdminHash(): string {
  if (fs.existsSync(ADMIN_AUTH_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(ADMIN_AUTH_FILE, 'utf8'));
      if (data?.passwordHash) return data.passwordHash;
    } catch {
      // regenerate below
    }
  }
  const initialPassword = process.env.MS_ADMIN_INITIAL_PASSWORD || 'dms1100';
  const passwordHash = hashPassword(initialPassword);
  fs.writeFileSync(ADMIN_AUTH_FILE, JSON.stringify({ passwordHash, updatedAt: new Date().toISOString() }, null, 2));
  return passwordHash;
}

function signSessionToken(payload: Record<string, unknown>): string {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

function verifySessionToken(token: string): Record<string, unknown> | null {
  if (!token || !token.includes('.')) return null;
  const [encoded, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  try {
    const data = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (typeof data.exp === 'number' && data.exp < Date.now()) return null;
    return data;
  } catch {
    return null;
  }
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  app.post('/api/admin/login', (req, res) => {
    const clientIp = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'local').split(',')[0].trim();
    const now = Date.now();
    const record = attemptStore.get(clientIp);
    if (record && record.lockedUntil > now) {
      const waitSec = Math.ceil((record.lockedUntil - now) / 1000);
      return res.status(429).json({
        error: `Too many failed attempts. Try again in ${waitSec} seconds.`,
        lockedUntil: record.lockedUntil,
      });
    }

    const password = String(req.body?.password || '');
    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }

    const storedHash = getStoredAdminHash();
    if (!verifyPasswordHash(password, storedHash)) {
      const nextCount = (record && record.lockedUntil <= now ? record.count : 0) + 1;
      const lockedUntil = nextCount >= MAX_ATTEMPTS ? now + LOCKOUT_MS : 0;
      attemptStore.set(clientIp, { count: nextCount, lockedUntil });
      return res.status(401).json({
        error: lockedUntil
          ? 'Too many incorrect attempts. Locked for 15 minutes.'
          : `Incorrect password. ${MAX_ATTEMPTS - nextCount} attempts remaining.`,
      });
    }

    attemptStore.delete(clientIp);
    const token = signSessionToken({
      role: 'admin',
      iat: now,
      exp: now + 12 * 60 * 60 * 1000,
    });
    return res.json({ ok: true, sessionToken: token });
  });

  app.post('/api/admin/verify', (req, res) => {
    const token = String(req.body?.sessionToken || '');
    const decoded = verifySessionToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(401).json({ ok: false });
    }
    return res.json({ ok: true });
  });

  app.post('/api/admin/change-password', (req, res) => {
    const token = String(req.body?.sessionToken || '');
    const decoded = verifySessionToken(token);
    if (!decoded || decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const currentPassword = String(req.body?.currentPassword || '');
    const newPassword = String(req.body?.newPassword || '');
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }
    const storedHash = getStoredAdminHash();
    if (!verifyPasswordHash(currentPassword, storedHash)) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    const newHash = hashPassword(newPassword);
    fs.writeFileSync(ADMIN_AUTH_FILE, JSON.stringify({ passwordHash: newHash, updatedAt: new Date().toISOString() }, null, 2));
    return res.json({ ok: true });
  });

  app.post('/api/admin/stock-alert-email', async (req, res) => {
    const isAuthorized = await verifyAdminRequest(req);
    if (!isAuthorized) {
      return res.status(403).json({ error: 'Unauthorized admin session' });
    }

    const toEmail = String(req.body?.toEmail || BOOTSTRAP_ADMIN_EMAIL).trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(toEmail)) {
      return res.status(400).json({ error: 'Valid recipient email address is required' });
    }

    interface StockAlertItem {
      productId: string;
      sku: string;
      productName: string;
      stock: number;
      threshold: number;
    }

    const rawItems: unknown[] = Array.isArray(req.body?.items) ? req.body.items : [];
    const items: StockAlertItem[] = rawItems
      .filter((it: unknown): it is Record<string, unknown> => Boolean(it && typeof it === 'object'))
      .slice(0, 100)
      .map((it: Record<string, unknown>): StockAlertItem => ({
        productId: String(it.productId || '').slice(0, 128),
        sku: String(it.sku || 'N/A').slice(0, 80),
        productName: String(it.productName || 'Product').slice(0, 200),
        stock: Math.max(0, Number(it.stock || 0)),
        threshold: Math.max(0, Number(it.threshold || 5)),
      }));

    if (!items.length) {
      return res.status(400).json({ error: 'At least one low-stock item is required' });
    }

    const subject = items.length === 1
      ? `[MS FASHION] Low Stock Alert: ${items[0].sku} (${items[0].stock} left)`
      : `[MS FASHION] Low Stock Alert: ${items.length} SKUs Below Threshold`;

    const lines = items.map(
      (it: StockAlertItem, i: number) => `${i + 1}. SKU: ${it.sku} | ${it.productName} | Current Stock: ${it.stock} (Min Threshold: ${it.threshold})`
    );
    const textBody = [
      'MS FASHION Inventory Threshold Alert',
      `Generated: ${new Date().toISOString()}`,
      '',
      'The following SKUs have dropped below their configured minimum stock threshold:',
      ...lines,
      '',
      'Please review and restock in the Admin Inventory dashboard.',
    ].join('\n');

    const escapeHtml = (s: string) => s
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');

    const htmlRows = items
      .map((it: StockAlertItem) => `<tr><td style="padding:8px;border:1px solid #e4e4e7;font-family:monospace;">${escapeHtml(it.sku)}</td><td style="padding:8px;border:1px solid #e4e4e7;">${escapeHtml(it.productName)}</td><td style="padding:8px;border:1px solid #e4e4e7;font-weight:700;color:#b91c1c;">${it.stock}</td><td style="padding:8px;border:1px solid #e4e4e7;">${it.threshold}</td></tr>`)
      .join('');
    const htmlBody = `
      <div style="font-family:sans-serif;color:#111111;max-width:640px;">
        <h2 style="margin:0 0 8px;">MS FASHION Low Stock Alert</h2>
        <p style="margin:0 0 14px;color:#52525b;">The following product SKUs have dropped below their configured minimum stock value:</p>
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          <thead>
            <tr style="background:#f7f7f6;">
              <th style="padding:8px;border:1px solid #e4e4e7;text-align:left;">SKU</th>
              <th style="padding:8px;border:1px solid #e4e4e7;text-align:left;">Product</th>
              <th style="padding:8px;border:1px solid #e4e4e7;text-align:left;">Stock</th>
              <th style="padding:8px;border:1px solid #e4e4e7;text-align:left;">Min Threshold</th>
            </tr>
          </thead>
          <tbody>${htmlRows}</tbody>
        </table>
      </div>
    `;

    const resendKey = String(process.env.RESEND_API_KEY || '').trim();
    if (resendKey) {
      try {
        const resendResp = await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${resendKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            from: process.env.ALERT_FROM_EMAIL || 'MS FASHION Alerts <onboarding@resend.dev>',
            to: [toEmail],
            subject,
            text: textBody,
            html: htmlBody,
          }),
        });
        const resendData = (await resendResp.json().catch(() => ({}))) as { id?: string; message?: string };
        if (resendResp.ok) {
          return res.json({ ok: true, mode: 'resend', id: resendData.id || '', toEmail, subject });
        }
        return res.status(502).json({ error: resendData.message || 'Email provider rejected request' });
      } catch (err) {
        return res.status(502).json({ error: err instanceof Error ? err.message : 'Email delivery failed' });
      }
    }

    const webhookUrl = String(process.env.ALERT_WEBHOOK_URL || '').trim();
    if (webhookUrl) {
      try {
        const whResp = await fetch(webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ toEmail, subject, text: textBody, html: htmlBody, items }),
        });
        if (whResp.ok) {
          return res.json({ ok: true, mode: 'webhook', toEmail, subject });
        }
      } catch {
        // fall through to outbox + mailto fallback
      }
    }

    let existingOutbox: unknown[] = [];
    try {
      if (fs.existsSync(ALERT_OUTBOX_FILE)) {
        const parsed = JSON.parse(fs.readFileSync(ALERT_OUTBOX_FILE, 'utf8'));
        if (Array.isArray(parsed)) existingOutbox = parsed;
      }
    } catch {
      existingOutbox = [];
    }
    const entry = {
      id: `email_${Date.now()}`,
      toEmail,
      subject,
      text: textBody,
      items,
      createdAt: new Date().toISOString(),
    };
    try {
      fs.writeFileSync(ALERT_OUTBOX_FILE, JSON.stringify([entry, ...existingOutbox].slice(0, 50), null, 2));
    } catch {
      // ignore disk write issues in read-only environments
    }

    const mailtoUrl = `mailto:${encodeURIComponent(toEmail)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(textBody)}`;
    return res.json({
      ok: true,
      mode: 'mailto_fallback',
      toEmail,
      subject,
      mailtoUrl,
      sentAt: entry.createdAt,
    });
  });

  app.get('/api/social/oembed', async (req, res) => {
    const rawUrl = String(req.query.url || '').trim();
    if (!rawUrl) {
      return res.status(400).json({ error: 'Missing url query parameter' });
    }
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(rawUrl);
    } catch {
      return res.status(400).json({ error: 'Invalid URL' });
    }
    if (!['https:', 'http:'].includes(parsedUrl.protocol)) {
      return res.status(400).json({ error: 'Invalid URL protocol' });
    }
    const host = parsedUrl.hostname.toLowerCase();
    const isTikTok = host === 'tiktok.com' || host.endsWith('.tiktok.com');
    const isInstagram = host === 'instagram.com' || host.endsWith('.instagram.com');
    if (!isTikTok && !isInstagram) {
      return res.status(400).json({ error: 'Only TikTok and Instagram URLs are supported' });
    }

    const endpoint = isTikTok
      ? `https://www.tiktok.com/oembed?url=${encodeURIComponent(parsedUrl.toString())}`
      : `https://www.instagram.com/api/v1/oembed/?url=${encodeURIComponent(parsedUrl.toString())}`;

    try {
      const upstream = await fetch(endpoint, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; MSFashionStorefront/1.0)',
          Accept: 'application/json',
        },
        signal: AbortSignal.timeout(8000),
      });
      if (!upstream.ok) {
        return res.status(502).json({ error: `oEmbed upstream returned ${upstream.status}` });
      }
      const data = (await upstream.json()) as Record<string, unknown>;
      const htmlStr = typeof data.html === 'string' ? data.html : '';
      const srcMatch = htmlStr.match(/<iframe[^>]+src=["']([^"']+)["']/i);
      return res.json({
        ok: true,
        platform: isTikTok ? 'tiktok' : 'instagram',
        postUrl: parsedUrl.toString(),
        title: typeof data.title === 'string' ? data.title : '',
        authorName: typeof data.author_name === 'string' ? data.author_name : '',
        authorUrl: typeof data.author_url === 'string' ? data.author_url : '',
        thumbnailUrl: typeof data.thumbnail_url === 'string' ? data.thumbnail_url : '',
        embedProductId: typeof data.embed_product_id === 'string' ? data.embed_product_id : '',
        embedUrl: srcMatch ? srcMatch[1] : '',
        html: htmlStr,
      });
    } catch (err) {
      return res.status(502).json({
        error: err instanceof Error ? err.message : 'Failed to fetch social oEmbed',
      });
    }
  });

  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`MS FASHION server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
