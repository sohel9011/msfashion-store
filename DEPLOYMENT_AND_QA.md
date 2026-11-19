# MS FASHION – Firebase Deployment & QA Guide

## 1. Provisioned Firebase Project
- **Project ID:** `turing-reducer-k5v9p`
- **Firestore Database ID:** `ai-studio-4e898927-dbee-4c10-bb58-4d76b9b84288`
- **Storage Bucket:** `turing-reducer-k5v9p.firebasestorage.app`
- **Auth Domain:** `turing-reducer-k5v9p.firebaseapp.com`
- **Rules Status:** `firestore.rules` has been audited with `@firebase/eslint-plugin-security-rules` (0 errors) and deployed to the project.

## 2. Firebase Console Steps Required Before Broad Launch
1. **Authentication Providers:**
   - Open Firebase Console -> Authentication -> Sign-in method.
   - Google Sign-In is configured by provisioning.
   - Enable **Email/Password** if you want customer email/password sign-up and password reset links to work for customers.
2. **Firebase Storage:**
   - Open Firebase Console -> Storage -> Get Started (if not yet initialized on the bucket) so product, category, banner, and logo uploads succeed.
   - Deploy Storage rules: `firebase deploy --only storage`
3. **Cloud Functions (Production Password-Only Custom Token + Server-Side Order Verification):**
   - Note: Firebase Cloud Functions v2 requires the **Blaze** plan.
   - Install function dependencies and deploy:
     ```bash
     cd functions && npm install && cd ..
     firebase deploy --only functions,firestore:indexes,storage
     ```
   - Set `localStorage.setItem('msf_cf_base', 'https://<region>-turing-reducer-k5v9p.cloudfunctions.net')` or configure Hosting rewrites so `verifyAdminPassword`, `changeAdminPassword`, `createOrder`, and `updateOrderStatus` route directly to your Cloud Functions.
   - Initial admin password is configured server-side (`MS_ADMIN_INITIAL_PASSWORD`, defaulting to `dms1100` on first initialization in `admin_secrets/config` or `.admin-auth.json` in preview). Change it immediately from **Admin Dashboard -> 17. Admin Password**.
4. **Firebase Hosting (Optional):**
   ```bash
   npm run build
   firebase deploy --only hosting
   ```

## 3. Emulator Testing
Run the Firestore security rules test suite against the Firebase Emulator:
```bash
firebase emulators:start --only firestore,auth,storage,functions
```
Verify all 12 "Dirty Dozen" adversarial cases documented in `security_spec.md` and `firestore.rules.test.ts` return `PERMISSION_DENIED`.

## 4. Mobile & End-to-End QA Checklist
- [x] **Responsive Viewport Audit:** Verified `overflow-x: clip`, `box-sizing: border-box`, `min-width: 0` on all grids/flex children across `320px`, `360px`, `375px`, `390px`, `414px`, `430px`, `768px`, `1024px`, `1280px`, `1440px`.
- [x] **Product Image Ratio:** Enforced `aspect-ratio: 39 / 43` with `object-fit: contain` (no cropped sleeves, collars, or trouser legs).
- [x] **Hidden Admin Login:** Triple-tap the MS FASHION footer logo within 2 seconds -> password-only modal (`dms1100`) -> Admin Dashboard opens immediately with no email or OTP step.
- [x] **Unlimited Catalog & Batch Image Upload:** No artificial cap on product count or product image count; client-side WebP compression, per-file progress, overall progress, retry failed, reorder, main image selection.
- [x] **Complete Orders & WhatsApp Flow:** Validates cart/stock -> writes full order snapshot (including image URLs) to `orders`, `order_tracking`, and `notifications` BEFORE opening `wa.me/8801604703820`, with retry link.
- [x] **Admin Order Details:** Real-time `onSnapshot` order updates, new order alert badge, full product table displaying each item's saved image snapshot, status/tracking updates, stock restoration on cancellation, and invoice printing.
