import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const ADMIN_AUTH_FILE = path.resolve(process.cwd(), '.admin-auth.json');
const SESSION_SECRET = process.env.ADMIN_SESSION_SECRET || crypto.createHash('sha256').update(process.env.APP_URL || 'ms-fashion-secret-key').digest('hex');

const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const attemptStore = new Map<string, { count: number; lockedUntil: number }>();

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
