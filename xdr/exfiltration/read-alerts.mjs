import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SECRET_ASSIGNMENT_PATTERN = /(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|bearer|authorization)\s*[:=]\s*[^\s,;]+/giu;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/gu;
const PRIVATE_KEY_PATTERN = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/gu;
const RAW_TOKEN_PATTERN = /\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16})\b/gu;
const LONG_OPAQUE_VALUE_PATTERN = /^[A-Za-z0-9_+/=-]{48,}$/u;

export function sanitizeText(value) {
  if (typeof value !== 'string') return '';
  let cleaned = value
    .replace(SECRET_ASSIGNMENT_PATTERN, '[REDACTED]')
    .replace(JWT_PATTERN, '[REDACTED]')
    .replace(PRIVATE_KEY_PATTERN, '[REDACTED]')
    .replace(RAW_TOKEN_PATTERN, '[REDACTED]')
    .replace(/[\r\n\t]+/gu, ' ')
    .trim();

  if (LONG_OPAQUE_VALUE_PATTERN.test(cleaned)) cleaned = '[REDACTED]';
  return cleaned;
}

export function extractAlertSummary(alert) {
  return {
    timestamp: sanitizeText(alert?.timestamp),
    srcip: sanitizeText(alert?.data?.srcip),
    srcuser: sanitizeText(alert?.data?.srcuser),
    level: Number.isFinite(alert?.rule?.level) ? alert.rule.level : null,
    description: sanitizeText(alert?.rule?.description),
  };
}

export async function readExfiltrationAlerts(fixturePath) {
  const defaultPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'exfiltration.json');
  const raw = await readFile(fixturePath || defaultPath, 'utf8');
  const parsed = JSON.parse(raw);
  const alerts = Array.isArray(parsed?.alerts) ? parsed.alerts : [];
  return alerts.map(extractAlertSummary);
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const summaries = await readExfiltrationAlerts(process.argv[2]);
  for (const item of summaries) {
    console.log(JSON.stringify(item));
  }
}
