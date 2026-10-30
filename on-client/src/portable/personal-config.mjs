// Server only. The file contains preferences; credentials come only from the server environment.
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';

const MAX_BYTES = 16 * 1024;
const fail = () => Object.assign(new Error('PERSONAL_CONFIG_INVALID'), { code: 'PERSONAL_CONFIG_INVALID' });
const samePath = (a, b) => process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const fields = (value, required, optional = []) => record(value)
  && required.every(key => Object.hasOwn(value, key))
  && Object.keys(value).every(key => required.includes(key) || optional.includes(key));

export function isPersonalModelId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$/.test(value)
    && !/(?:astra|flash)/i.test(value);
}

async function inspectPath(file) {
  // Check every ancestor as well as the final file: junctions and symlinks are not configuration paths.
  let current = path.parse(file).root;
  for (const part of file.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const stat = await lstat(current);
    if (stat.isSymbolicLink() || !samePath(path.resolve(await realpath(current)), current)) throw fail();
  }
  const stat = await lstat(file);
  if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_BYTES) throw fail();
  return stat;
}

function configuration(value, env) {
  if (!fields(value, ['schema', 'ai'], ['appName']) || value.schema !== 'keshev.personal-config.v1'
      || !fields(value.ai, ['enabled', 'provider', 'model']) || typeof value.ai.enabled !== 'boolean'
      || !['openai', 'openrouter', 'xai'].includes(value.ai.provider) || !isPersonalModelId(value.ai.model)) throw fail();
  if (value.appName !== undefined && typeof value.appName !== 'string') throw fail();
  const rawName = value.appName ?? '';
  if (/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069<>]/u.test(rawName)) throw fail();
  const appName = rawName.normalize('NFC').trim() || '케셰브';
  if ([...appName].length > 32) throw fail();
  let apiKey;
  if (value.ai.enabled) {
    apiKey = env.KESHEV_PERSONAL_API_KEY;
    if (typeof apiKey !== 'string' || !/^[\x21-\x7e]{8,4096}$/.test(apiKey)) throw fail();
  }
  return Object.freeze({ appName, ai: Object.freeze({ ...value.ai, apiKey }) });
}

export async function readPersonalConfiguration({ file, projectRoot, env = process.env } = {}) {
  if (file === undefined) return configuration({ schema: 'keshev.personal-config.v1', ai: {
    enabled: false, provider: 'openai', model: 'gpt-6.1-sol',
  } }, env);
  let handle;
  try {
    if (typeof file !== 'string' || !path.isAbsolute(file) || file.includes('\0')
        || typeof projectRoot !== 'string' || !path.isAbsolute(projectRoot)) throw fail();
    // Reject alternate data streams and Windows device path aliases.
    if (process.platform === 'win32' && (file.startsWith('\\\\') || file.slice(2).includes(':'))) throw fail();
    const target = path.resolve(file);
    const root = path.resolve(await realpath(projectRoot));
    const relative = path.relative(root, target);
    if (relative === '' || !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative)) throw fail();
    const before = await inspectPath(target);
    handle = await open(target, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 || opened.size > MAX_BYTES
        || opened.dev !== before.dev || opened.ino !== before.ino) throw fail();
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let total = 0;
    while (total < buffer.length) {
      const { bytesRead } = await handle.read(buffer, total, buffer.length - total, total);
      if (!bytesRead) break;
      total += bytesRead;
    }
    if (total > MAX_BYTES) throw fail();
    const after = await inspectPath(target);
    const final = await handle.stat();
    if (after.dev !== opened.dev || after.ino !== opened.ino || final.nlink !== 1
        || final.size !== total || final.mtimeMs !== opened.mtimeMs || after.mtimeMs !== opened.mtimeMs) throw fail();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, total));
    return configuration(JSON.parse(text), env);
  } catch { throw fail(); }
  finally { await handle?.close().catch(() => {}); }
}
