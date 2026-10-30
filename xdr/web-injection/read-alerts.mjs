import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SECRET_VALUE_PATTERN = /(?:password|passwd|secret|token|apikey|api_key|private_key|bearer)\s*[:=]\s*\S+|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/giu;

export function sanitizeText(value) {
  if (typeof value !== 'string') return '';
  return value.replace(SECRET_VALUE_PATTERN, '[REDACTED]').replace(/\r?\n/gu, ' ').trim();
}

export function extractAlertSummary(alert) {
  return {
    timestamp: typeof alert?.timestamp === 'string' ? sanitizeText(alert.timestamp) : '',
    srcip: typeof alert?.data?.srcip === 'string' ? sanitizeText(alert.data.srcip) : '',
    srcuser: typeof alert?.data?.srcuser === 'string' ? sanitizeText(alert.data.srcuser) : '',
    level: typeof alert?.rule?.level === 'number' ? alert.rule.level : null,
    description: typeof alert?.rule?.description === 'string' ? sanitizeText(alert.rule.description) : '',
  };
}

export async function readWebInjectionAlerts(fixturePath) {
  const defaultPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'web-injection.json');
  const raw = await readFile(fixturePath || defaultPath, 'utf8');
  const parsed = JSON.parse(raw);
  const alerts = Array.isArray(parsed?.alerts) ? parsed.alerts : [];
  return alerts.map(extractAlertSummary);
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const summaries = await readWebInjectionAlerts(process.argv[2]);
  for (const item of summaries) {
    console.log(JSON.stringify(item));
  }
}
