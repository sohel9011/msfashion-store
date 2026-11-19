# MS FASHION Firestore Security Specification (Phase 0 TDD)

## 1. Data Invariants
1. **Identity Integrity**: A `users/{userId}`, `wishlists/{userId}`, or `carts/{userId}` document may only be read or written by the authenticated user whose `request.auth.uid == userId` or by a verified administrator (`isAdmin()`).
2. **Privilege Isolation**: No client may create or modify `/admins/{uid}`, `/admin_secrets/{docId}`, or `/admin_rate_limits/{docId}`. Customers cannot escalate roles or write `role` fields in `/users/{userId}`.
3. **Cost & Profit Privacy**: `product_private/{productId}` (containing `costPrice` and supplier margins) is strictly readable and writable only by `isAdmin()`.
4. **Order Integrity & PII Isolation**:
   - `orders/{orderId}` contains customer PII (`phone`, `email`, `address`) and is strictly readable (`get` and `list`) only by the owner (`resource.data.userId == request.auth.uid`) or `isAdmin()`.
   - On creation, an order must start with `orderStatus == 'Pending'` and `paymentStatus in ['Unpaid', 'Pending Verification']`, with `createdAt == request.time`, `updatedAt == request.time`, valid items list (`size() >= 1 && size() <= 100`), and non-negative financial totals.
   - Only `isAdmin()` may update `paymentStatus`, `finalTotal`, `adminNotes`, or advance `orderStatus` beyond customer cancellation of a `'Pending'` order.
5. **Non-PII Tracking**: `order_tracking/{orderId}` allows single-document `get` by exact `orderId` (no `list`) and must never contain `phone`, `email`, `address`, or `customerName`.
6. **Public Catalog Integrity**: Only `isAdmin()` may create, update, or delete `products`, `categories`, `banners`, `coupons`, `settings`, or `inventoryLogs`.
7. **Review Moderation**: Only signed-in verified users (`request.auth.uid == incoming().userId`) may create reviews with `status == 'pending'`; only `isAdmin()` may set `status` to `'approved'` or `'rejected'`.
8. **Temporal & Boundary Enforcement**: All string fields have `.size()` upper bounds, all IDs match `^[a-zA-Z0-9_-]+$`, and `createdAt`/`updatedAt` must equal `request.time`.

## 2. The "Dirty Dozen" Adversarial Payloads (Must Return PERMISSION_DENIED)
1. **Self-Admin Escalation**: Unprivileged user attempts `setDoc(doc(db, 'admins', uid), { uid, role: 'super_admin' })`.
2. **Shadow Field Injection on User Profile**: Authenticated user sends `{ uid, name: 'Test', email: 'a@b.com', isAdmin: true, createdAt: serverTimestamp(), updatedAt: serverTimestamp() }` to `/users/{uid}`.
3. **Cross-User PII Read**: Authenticated User A attempts `getDoc(doc(db, 'users', userB_uid))`.
4. **Order Listing Scraping**: Authenticated User A attempts `getDocs(collection(db, 'orders'))` without filtering `where('userId', '==', userA_uid)`.
5. **Order Price/Status Spoofing on Create**: Customer creates `/orders/MSF-20261119-9999` with `orderStatus: 'Delivered'` and `paymentStatus: 'Paid'`.
6. **Customer Order Total Tampering on Update**: Authenticated owner updates `/orders/{id}` changing `finalTotal: 1`.
7. **Product Cost Price Leak**: Public visitor or customer attempts `getDoc(doc(db, 'product_private', 'prod_1'))`.
8. **Unauthorized Product Write**: Customer attempts `setDoc(doc(db, 'products', 'fake_1'), { ... })`.
9. **Review Auto-Approval Spoofing**: Customer submits `/reviews/rev_1` with `status: 'approved'` directly.
10. **ID Poisoning (Resource Exhaustion)**: Attacker targets `/products/` + 1500-char ID or `/orders/` + `invalid$id!`.
11. **Timestamp Forgery**: User creates `/orders/MSF-20261119-0001` with `createdAt: new Date('2020-01-01')` instead of `request.time`.
12. **Public Settings Hijack**: Non-admin user attempts `updateDoc(doc(db, 'settings', 'public'), { whatsappNumber: '+1999999999' })`.
