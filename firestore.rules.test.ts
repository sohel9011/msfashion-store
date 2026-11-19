/**
 * Firebase Emulator Suite Security Rules Test Runner for MS FASHION
 * Covers the "Dirty Dozen" adversarial payloads defined in security_spec.md.
 * Run with: firebase emulators:exec --only firestore "npx vitest run firestore.rules.test.ts"
 */
import { readFileSync } from 'node:fs';

// Note: Install @firebase/rules-unit-testing & vitest in dev environment when running against Firestore Emulator.
export const DIRTY_DOZEN_SPECS = [
  '1. Self-Admin Escalation -> /admins/{uid} must deny client writes',
  '2. Shadow Field Injection -> /users/{uid} with isAdmin:true must deny',
  '3. Cross-User PII Read -> User A reading /users/{userB} must deny',
  '4. Order Listing Scraping -> Unfiltered list on /orders must deny for non-admin',
  '5. Order Status/Payment Spoofing -> Creating order with Delivered/Paid must deny',
  '6. Customer Order Total Tampering -> Updating finalTotal on /orders/{id} must deny',
  '7. Product Cost Price Leak -> Non-admin reading /product_private/{id} must deny',
  '8. Unauthorized Product Write -> Non-admin writing /products/{id} must deny',
  '9. Review Auto-Approval Spoofing -> Creating review with status:approved must deny',
  '10. ID Poisoning -> Writing >128 char or invalid chars doc ID must deny',
  '11. Timestamp Forgery -> Creating order with forged createdAt != request.time must deny',
  '12. Public Settings Hijack -> Non-admin updating /settings/public must deny',
];

export function loadRulesText(): string {
  return readFileSync('firestore.rules', 'utf8');
}
