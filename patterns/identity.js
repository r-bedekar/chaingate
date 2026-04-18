// Canonical publisher identity key construction.
//
// Returns the string used as an object key for tenure and transition
// detection in patterns/publisher.js. Convention follows git author
// strings — `"name <email>"` when both are present — so the format is
// human-readable and familiar to anyone reading a gate decision log.
//
// Normalization rules:
//   - Both fields are trimmed.
//   - Email is lowercased (RFC 5321 local-parts are case-sensitive in
//     theory but case-insensitive in practice across all major
//     providers; lowercasing collapses an attacker's case-variant
//     dodge and has no legitimate downside).
//   - Name is preserved as-is after trimming (display variations like
//     "Dominic Tarr" vs "dominictarr" are real signal, not noise;
//     treat them as distinct identities at this layer).
//   - If neither field yields a value, return null (caller must count
//     the row as skipped; do NOT use a synthetic placeholder — that
//     would silently collapse separate-but-missing identities into
//     one "tenure block").

export function normalizeIdentity(emailRaw, nameRaw) {
  const email = typeof emailRaw === 'string' ? emailRaw.trim().toLowerCase() : '';
  const name = typeof nameRaw === 'string' ? nameRaw.trim() : '';
  if (!email && !name) return null;
  if (email && name) return `${name} <${email}>`;
  if (email) return `<${email}>`;
  return name;
}
