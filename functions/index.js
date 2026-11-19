const { onRequest } = require('firebase-functions/v2/https');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors')({ origin: true });

if (!admin.apps.length) {
  admin.initializeApp();
}

const FIRESTORE_DATABASE_ID = process.env.FIRESTORE_DATABASE_ID || 'ai-studio-4e898927-dbee-4c10-bb58-4d76b9b84288';
const db = FIRESTORE_DATABASE_ID && FIRESTORE_DATABASE_ID !== '(default)'
  ? admin.firestore(FIRESTORE_DATABASE_ID)
  : admin.firestore();

const ADMIN_UID = 'ms_fashion_admin';
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

function hashPassword(password, salt) {
  const usedSalt = salt || crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, usedSalt, 64).toString('hex');
  return `${usedSalt}:${derived}`;
}

function verifyPasswordHash(password, storedHash) {
  const parts = String(storedHash || '').split(':');
  if (parts.length !== 2) return false;
  const [salt, keyHex] = parts;
  const derived = crypto.scryptSync(password, salt, 64);
  const keyBuf = Buffer.from(keyHex, 'hex');
  if (derived.length !== keyBuf.length) return false;
  return crypto.timingSafeEqual(derived, keyBuf);
}

async function ensureAdminSecretExists() {
  const ref = db.collection('admin_secrets').doc('config');
  const snap = await ref.get();
  if (!snap.exists) {
    const initialPassword = process.env.MS_ADMIN_INITIAL_PASSWORD || 'dms1100';
    const passwordHash = hashPassword(initialPassword);
    await ref.set({
      passwordHash,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    return passwordHash;
  }
  return snap.data().passwordHash;
}

function getClientKey(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : (req.ip || 'unknown');
  return crypto.createHash('sha256').update(ip).digest('hex').slice(0, 32);
}

async function verifyAdminBearer(req) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) return null;
  const idToken = authHeader.slice(7).trim();
  const decoded = await admin.auth().verifyIdToken(idToken);
  if (decoded.uid === ADMIN_UID || decoded.admin === true || (decoded.email === 'sohel901190@gmail.com' && decoded.email_verified)) {
    return decoded;
  }
  const adminDoc = await db.collection('admins').doc(decoded.uid).get();
  if (adminDoc.exists) return decoded;
  return null;
}

exports.verifyAdminPassword = onRequest((req, res) => {
  cors(req, res, async () => {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
    try {
      const password = String(req.body?.password || '');
      if (!password) {
        return res.status(400).json({ error: 'Password is required' });
      }

      const clientKey = getClientKey(req);
      const rateRef = db.collection('admin_rate_limits').doc(clientKey);
      const rateSnap = await rateRef.get();
      const now = Date.now();

      if (rateSnap.exists) {
        const rateData = rateSnap.data();
        if (rateData.lockedUntil && rateData.lockedUntil > now) {
          const waitSec = Math.ceil((rateData.lockedUntil - now) / 1000);
          return res.status(429).json({
            error: `Too many failed attempts. Try again in ${waitSec} seconds.`,
            lockedUntil: rateData.lockedUntil,
          });
        }
      }

      const storedHash = await ensureAdminSecretExists();
      const valid = verifyPasswordHash(password, storedHash);

      if (!valid) {
        const prevAttempts = rateSnap.exists && (!rateSnap.data().lockedUntil || rateSnap.data().lockedUntil <= now)
          ? Number(rateSnap.data().attempts || 0)
          : 0;
        const nextAttempts = prevAttempts + 1;
        const lockedUntil = nextAttempts >= MAX_ATTEMPTS ? now + LOCKOUT_MS : 0;
        await rateRef.set({
          attempts: nextAttempts,
          lockedUntil,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        return res.status(401).json({
          error: lockedUntil
            ? 'Too many incorrect attempts. Locked for 15 minutes.'
            : `Incorrect password. ${MAX_ATTEMPTS - nextAttempts} attempts remaining.`,
        });
      }

      await rateRef.delete().catch(() => {});

      await db.collection('admins').doc(ADMIN_UID).set({
        uid: ADMIN_UID,
        role: 'super_admin',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });

      const customToken = await admin.auth().createCustomToken(ADMIN_UID, { admin: true });
      return res.status(200).json({ ok: true, customToken, uid: ADMIN_UID });
    } catch (err) {
      console.error('verifyAdminPassword error:', err);
      return res.status(500).json({ error: 'Authentication verification failed' });
    }
  });
});

exports.changeAdminPassword = onRequest((req, res) => {
  cors(req, res, async () => {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
    try {
      const decoded = await verifyAdminBearer(req);
      if (!decoded) {
        return res.status(403).json({ error: 'Unauthorized admin request' });
      }
      const currentPassword = String(req.body?.currentPassword || '');
      const newPassword = String(req.body?.newPassword || '');
      if (newPassword.length < 6) {
        return res.status(400).json({ error: 'New password must be at least 6 characters' });
      }
      const storedHash = await ensureAdminSecretExists();
      if (!verifyPasswordHash(currentPassword, storedHash)) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }
      const newHash = hashPassword(newPassword);
      await db.collection('admin_secrets').doc('config').set({
        passwordHash: newHash,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      return res.status(200).json({ ok: true });
    } catch (err) {
      console.error('changeAdminPassword error:', err);
      return res.status(500).json({ error: 'Failed to update admin password' });
    }
  });
});

function generateOrderId() {
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, '0');
  const d = String(now.getUTCDate()).padStart(2, '0');
  const rand = String(Math.floor(1000 + Math.random() * 9000));
  return `MSF-${y}${m}${d}-${rand}`;
}

exports.createOrder = onRequest((req, res) => {
  cors(req, res, async () => {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
    try {
      const body = req.body || {};
      const items = Array.isArray(body.items) ? body.items : [];
      if (items.length === 0 || items.length > 100) {
        return res.status(400).json({ error: 'Order must contain between 1 and 100 items' });
      }

      const customerName = String(body.customerName || '').trim().slice(0, 120);
      const phone = String(body.phone || '').trim().slice(0, 30);
      const email = String(body.email || '').trim().slice(0, 160);
      const district = String(body.district || '').trim().slice(0, 80);
      const city = String(body.city || '').trim().slice(0, 80);
      const address = String(body.address || '').trim().slice(0, 400);
      const instructions = String(body.instructions || '').trim().slice(0, 500);
      const paymentMethod = String(body.paymentMethod || 'Cash on Delivery');
      const paymentReference = String(body.paymentReference || '').trim().slice(0, 120);
      const orderSource = body.orderSource === 'WhatsApp' ? 'WhatsApp' : 'Checkout';
      const couponCode = String(body.couponCode || '').trim().toUpperCase().slice(0, 60);

      if (!customerName || !phone || !district || !address) {
        return res.status(400).json({ error: 'Missing required customer delivery fields' });
      }

      let uid = null;
      const authHeader = req.headers.authorization || '';
      if (authHeader.startsWith('Bearer ')) {
        try {
          const decoded = await admin.auth().verifyIdToken(authHeader.slice(7).trim());
          uid = decoded.uid;
        } catch (_) {
          uid = null;
        }
      }

      const settingsSnap = await db.collection('settings').doc('public').get();
      const settings = settingsSnap.exists ? settingsSnap.data() : {};
      if (!uid && settings.guestCheckoutEnabled === false) {
        return res.status(401).json({ error: 'Please sign in to place an order' });
      }

      const orderId = body.clientOrderId && /^MSF-[0-9]{8}-[0-9]{4}$/.test(body.clientOrderId)
        ? body.clientOrderId
        : generateOrderId();

      const result = await db.runTransaction(async (tx) => {
        const existingOrder = await tx.get(db.collection('orders').doc(orderId));
        if (existingOrder.exists) {
          return { duplicate: true, order: existingOrder.data() };
        }

        let subtotal = 0;
        const verifiedItems = [];

        for (const item of items) {
          const productId = String(item.productId || '');
          const qty = Math.max(1, Math.floor(Number(item.quantity || 1)));
          const prodRef = db.collection('products').doc(productId);
          const prodSnap = await tx.get(prodRef);
          if (!prodSnap.exists) {
            throw new Error(`Product not found: ${productId}`);
          }
          const prod = prodSnap.data();
          if (!prod.active || !prod.published) {
            throw new Error(`Product unavailable: ${prod.name}`);
          }

          let unitPrice = Number(prod.salePrice > 0 ? prod.salePrice : prod.regularPrice);
          let availableStock = Number(prod.stock || 0);
          let variantSku = prod.sku;

          const size = String(item.size || '').slice(0, 40);
          const color = String(item.color || '').slice(0, 40);

          if (Array.isArray(prod.variants) && prod.variants.length > 0 && (size || color)) {
            const matched = prod.variants.find((v) =>
              (!size || v.size === size) && (!color || v.color === color)
            );
            if (matched) {
              if (Number(matched.price) > 0) unitPrice = Number(matched.price);
              availableStock = Number(matched.stock ?? availableStock);
              if (matched.sku) variantSku = matched.sku;
            }
          }

          if (availableStock < qty) {
            throw new Error(`Insufficient stock for ${prod.name}`);
          }

          const newStock = Math.max(0, Number(prod.stock || 0) - qty);
          const updatedVariants = Array.isArray(prod.variants)
            ? prod.variants.map((v) => {
                if ((!size || v.size === size) && (!color || v.color === color)) {
                  return { ...v, stock: Math.max(0, Number(v.stock || 0) - qty) };
                }
                return v;
              })
            : [];

          tx.update(prodRef, {
            stock: newStock,
            soldCount: Number(prod.soldCount || 0) + qty,
            variants: updatedVariants,
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          });

          const logId = `log_${orderId}_${productId}`.slice(0, 120);
          tx.set(db.collection('inventoryLogs').doc(logId), {
            id: logId,
            productId,
            productName: prod.name,
            sku: variantSku,
            change: -qty,
            previousStock: Number(prod.stock || 0),
            newStock,
            reason: `Order ${orderId}`,
            orderId,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
          });

          const itemSubtotal = unitPrice * qty;
          subtotal += itemSubtotal;

          const mainImg = Array.isArray(prod.images) && prod.images.length > 0
            ? (prod.images.find((i) => i.isMain)?.url || prod.images[0].url || '')
            : '';

          verifiedItems.push({
            productId,
            productName: prod.name,
            productNameBn: prod.nameBn || prod.name,
            sku: variantSku,
            imageUrl: mainImg,
            size,
            color,
            quantity: qty,
            unitPrice,
            subtotal: itemSubtotal,
          });
        }

        let deliveryCharge = district.toLowerCase() === 'dhaka'
          ? Number(settings.dhakaDeliveryCharge ?? 70)
          : Number(settings.outsideDhakaDeliveryCharge ?? 130);

        if (settings.districtCharges && settings.districtCharges[district] !== undefined) {
          deliveryCharge = Number(settings.districtCharges[district]);
        }
        const freeThreshold = Number(settings.freeDeliveryThreshold || 0);
        if (freeThreshold > 0 && subtotal >= freeThreshold) {
          deliveryCharge = 0;
        }

        let discount = 0;
        let appliedCoupon = '';
        if (couponCode) {
          const couponRef = db.collection('coupons').doc(couponCode);
          const couponSnap = await tx.get(couponRef);
          if (couponSnap.exists) {
            const c = couponSnap.data();
            const today = new Date().toISOString().slice(0, 10);
            const withinStart = !c.startDate || today >= c.startDate;
            const withinExpiry = !c.expiryDate || today <= c.expiryDate;
            const underUsage = !c.usageLimit || Number(c.usedCount || 0) < Number(c.usageLimit);
            if (c.active && withinStart && withinExpiry && underUsage && subtotal >= Number(c.minOrder || 0)) {
              if (c.type === 'percentage') {
                discount = Math.round((subtotal * Number(c.amount || 0)) / 100);
                if (Number(c.maxDiscount || 0) > 0) {
                  discount = Math.min(discount, Number(c.maxDiscount));
                }
              } else if (c.type === 'fixed') {
                discount = Math.min(subtotal, Number(c.amount || 0));
              } else if (c.type === 'free_delivery') {
                deliveryCharge = 0;
              }
              appliedCoupon = couponCode;
              tx.update(couponRef, {
                usedCount: Number(c.usedCount || 0) + 1,
                updatedAt: admin.firestore.FieldValue.serverTimestamp(),
              });
            }
          }
        }

        const finalTotal = Math.max(0, subtotal - discount + deliveryCharge);
        const nowTs = admin.firestore.FieldValue.serverTimestamp();
        const paymentStatus = paymentMethod === 'Cash on Delivery' ? 'Unpaid' : 'Pending Verification';

        const orderDoc = {
          orderId,
          userId: uid,
          customerName,
          phone,
          email,
          district,
          city,
          address,
          instructions,
          items: verifiedItems,
          subtotal,
          discount,
          couponCode: appliedCoupon,
          deliveryCharge,
          finalTotal,
          paymentMethod,
          paymentStatus,
          paymentReference,
          orderStatus: 'Pending',
          orderSource,
          adminNotes: '',
          trackingNumber: '',
          courier: settings.defaultCourier || 'Steadfast / Pathao',
          createdAt: nowTs,
          updatedAt: nowTs,
        };

        tx.set(db.collection('orders').doc(orderId), orderDoc);
        tx.set(db.collection('order_tracking').doc(orderId), {
          orderId,
          orderStatus: 'Pending',
          paymentStatus,
          courier: orderDoc.courier,
          trackingNumber: '',
          itemCount: verifiedItems.reduce((sum, i) => sum + i.quantity, 0),
          finalTotal,
          createdAt: nowTs,
          updatedAt: nowTs,
        });

        const notifId = `notif_${orderId}`;
        tx.set(db.collection('notifications').doc(notifId), {
          id: notifId,
          userId: 'admin',
          orderId,
          title: `New Order ${orderId}`,
          message: `${customerName} (${phone}) placed a ৳${finalTotal} order via ${orderSource}.`,
          read: false,
          createdAt: nowTs,
        });

        return { duplicate: false, order: orderDoc };
      });

      return res.status(200).json({ ok: true, orderId, ...result });
    } catch (err) {
      console.error('createOrder error:', err);
      return res.status(400).json({ error: err.message || 'Order creation failed' });
    }
  });
});

exports.updateOrderStatus = onRequest((req, res) => {
  cors(req, res, async () => {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
    try {
      const decoded = await verifyAdminBearer(req);
      if (!decoded) {
        return res.status(403).json({ error: 'Unauthorized admin request' });
      }
      const { orderId, orderStatus, paymentStatus, trackingNumber, courier, adminNotes } = req.body || {};
      if (!orderId) return res.status(400).json({ error: 'orderId is required' });

      await db.runTransaction(async (tx) => {
        const orderRef = db.collection('orders').doc(orderId);
        const orderSnap = await tx.get(orderRef);
        if (!orderSnap.exists) throw new Error('Order not found');
        const prev = orderSnap.data();

        const nextStatus = orderStatus || prev.orderStatus;
        const restoreStatuses = ['Cancelled', 'Returned'];
        const shouldRestore = !restoreStatuses.includes(prev.orderStatus) && restoreStatuses.includes(nextStatus);

        if (shouldRestore && Array.isArray(prev.items)) {
          for (const item of prev.items) {
            const prodRef = db.collection('products').doc(item.productId);
            const prodSnap = await tx.get(prodRef);
            if (prodSnap.exists) {
              const p = prodSnap.data();
              const newStock = Number(p.stock || 0) + Number(item.quantity || 0);
              tx.update(prodRef, {
                stock: newStock,
                updatedAt: admin.firestore.FieldValue.serverTimestamp(),
              });
              const logId = `restore_${orderId}_${item.productId}_${Date.now()}`.slice(0, 120);
              tx.set(db.collection('inventoryLogs').doc(logId), {
                id: logId,
                productId: item.productId,
                productName: p.name,
                sku: item.sku || p.sku,
                change: Number(item.quantity || 0),
                previousStock: Number(p.stock || 0),
                newStock,
                reason: `Restored (${nextStatus}) ${orderId}`,
                orderId,
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
              });
            }
          }
        }

        const updates = {
          orderStatus: nextStatus,
          paymentStatus: paymentStatus || prev.paymentStatus,
          trackingNumber: trackingNumber !== undefined ? String(trackingNumber).slice(0, 120) : prev.trackingNumber,
          courier: courier !== undefined ? String(courier).slice(0, 120) : prev.courier,
          adminNotes: adminNotes !== undefined ? String(adminNotes).slice(0, 1000) : prev.adminNotes,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        };

        tx.update(orderRef, updates);
        tx.update(db.collection('order_tracking').doc(orderId), {
          orderStatus: updates.orderStatus,
          paymentStatus: updates.paymentStatus,
          trackingNumber: updates.trackingNumber || '',
          courier: updates.courier || '',
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        if (prev.userId) {
          const notifId = `status_${orderId}_${Date.now()}`.slice(0, 120);
          tx.set(db.collection('notifications').doc(notifId), {
            id: notifId,
            userId: prev.userId,
            orderId,
            title: `Order ${orderId}: ${nextStatus}`,
            message: `Your MS FASHION order status is now ${nextStatus}.`,
            read: false,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
          });
        }
      });

      return res.status(200).json({ ok: true });
    } catch (err) {
      console.error('updateOrderStatus error:', err);
      return res.status(400).json({ error: err.message || 'Failed to update order' });
    }
  });
});
