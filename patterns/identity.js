// Canonical publisher identity key construction.
//
// Returns the string used as an object key for tenure and transition
// detection in patterns/publisher.js. Priority order (three layers):
//
//   1. name present  → return name as-is (after trim)
//   2. email only    → return "<email>" with email lowercased
//   3. both missing  → return null (caller must count the row as skipped)
//
// Why name-primary, not the git-author "name <email>" form:
// the `publisher_name` field written by the npm collector is the
// account login from `_npmUser.name` in the registry metadata. npm
// sets this field server-side at publish time based on the
// authenticated account — it is NOT derived from package.json and
// cannot be spoofed by a publisher. Account logins are also globally
// unique across the npm registry, so the login alone is a stable,
// tamper-resistant identity key.
//
// By contrast, the email on a version record is stored alongside the
// account login but is not itself the authentication anchor — an
// account owner can change their registered email, and an attacker
// who compromises an account can change it too. Keying identity off
// the email turns a benign "person updated their email" into a
// spurious cold-handoff transition, which is exactly the lodash
// false-positive that motivated this scheme.
//
// Account-rename edge case: npm permits (rarely) renaming an account.
// A rename produces a tenure-block boundary (old-login → new-login)
// that looks identical to a real handoff at this layer. We do NOT
// heuristically merge login variants — any such heuristic is exactly
// the attack surface the account-login-as-key design closes. Renames
// must be resolved downstream by the W-window overlap signal and the
// K-threshold known-contributor signal; the gate is structured so
// that a rename on an active package will be flagged as known or
// overlapping, not cold.
//
// Normalization rules:
//   - Both fields are trimmed before evaluation.
//   - Email is lowercased in the fallback-form key. RFC 5321
//     local-parts are technically case-sensitive but every major
//     provider treats them as insensitive; lowercasing collapses an
//     attacker's case-variant dodge and has no legitimate downside.
//   - Name is preserved as-is after trimming. Display variations
//     (e.g. "Dominic Tarr" vs "dominictarr") are real signal at this
//     layer and must not be collapsed.
//   - Never synthesize a placeholder when both fields are missing —
//     that would silently fuse separate-but-missing identities into
//     one tenure block.

export function normalizeIdentity(emailRaw, nameRaw) {
  const email = typeof emailRaw === 'string' ? emailRaw.trim().toLowerCase() : '';
  const name = typeof nameRaw === 'string' ? nameRaw.trim() : '';
  if (name) return name;
  if (email) return `<${email}>`;
  return null;
}
