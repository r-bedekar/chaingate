const isTTY = process.stdout.isTTY && !process.env.NO_COLOR;

const CODES = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
};

function c(code, text) {
  if (!isTTY) return text;
  return `${code}${text}${CODES.reset}`;
}

export const fmt = {
  bold: (t) => c(CODES.bold, t),
  dim: (t) => c(CODES.dim, t),
  red: (t) => c(CODES.red, t),
  green: (t) => c(CODES.green, t),
  yellow: (t) => c(CODES.yellow, t),
  cyan: (t) => c(CODES.cyan, t),
  ok: (t) => c(CODES.green, `✓ ${t}`),
  warn: (t) => c(CODES.yellow, `⚠ ${t}`),
  fail: (t) => c(CODES.red, `✗ ${t}`),
  skip: (t) => c(CODES.cyan, `○ ${t}`),
  block: (t) => c(CODES.red, `🚫 ${t}`),
};

/**
 * Render a key-value table with aligned columns.
 * @param {Array<[string, string]>} rows
 */
export function renderTable(rows) {
  const maxKey = Math.max(...rows.map(([k]) => k.length));
  return rows
    .map(([k, v]) => `  ${fmt.bold(k.padEnd(maxKey))}  ${v}`)
    .join('\n');
}

/**
 * Format a disposition string with color.
 */
export function colorDisposition(disposition) {
  if (disposition === 'ALLOW') return fmt.green(disposition);
  if (disposition === 'WARN') return fmt.yellow(disposition);
  if (disposition === 'BLOCK') return fmt.red(disposition);
  return disposition;
}

/**
 * Render a gate result for `chaingate why` output.
 */
export function renderGate(gate) {
  const disp = colorDisposition(gate.result ?? gate.disposition);
  const name = fmt.bold(gate.gate ?? gate.name ?? 'unknown');
  const detail = gate.detail ? fmt.dim(` — ${gate.detail}`) : '';
  return `  ${disp} ${name}${detail}`;
}
