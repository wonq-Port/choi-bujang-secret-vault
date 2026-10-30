// Fixed official TLS endpoints only. No model discovery, redirects, retries, streaming, or tools.
import { types } from 'node:util';
import { isPersonalModelId } from './personal-config.mjs';

const bases = Object.freeze({ openai: 'https://api.openai.com/v1',
  openrouter: 'https://openrouter.ai/api/v1', xai: 'https://api.x.ai/v1' });
const ownError = Symbol('personal-http-error');
const fail = code => Object.assign(new Error(code), { code, [ownError]: true });
const record = value => value !== null && typeof value === 'object' && !types.isProxy(value)
  && Object.getPrototypeOf(value) === Object.prototype;
const fields = (value, keys) => record(value) && Reflect.ownKeys(value).length === keys.length
  && keys.every(key => Object.hasOwn(Object.getOwnPropertyDescriptor(value, key) ?? {}, 'value'));

function encodeBody(body, maxBytes) {
  if (!fields(body, ['model', 'messages', 'stream', 'response_format']) || !isPersonalModelId(body.model)
      || body.stream !== false || !fields(body.response_format, ['type']) || body.response_format.type !== 'json_object'
      || !Array.isArray(body.messages) || types.isProxy(body.messages) || body.messages.length !== 2) throw fail('PERSONAL_INVALID_REQUEST');
  for (let i = 0; i < 2; i++) {
    const descriptor = Object.getOwnPropertyDescriptor(body.messages, String(i));
    const message = descriptor?.value;
    if (!fields(message, ['role', 'content']) || message.role !== (i ? 'user' : 'system')
        || typeof message.content !== 'string') throw fail('PERSONAL_INVALID_REQUEST');
  }
  // Rebuild finite values so custom serializers and extra array properties cannot run.
  const messages = Array.from({ length: 2 }, (_, index) => {
    const { role, content } = Object.getOwnPropertyDescriptor(body.messages, String(index)).value;
    return { role, content };
  });
  const encoded = JSON.stringify({ model: body.model, messages,
    stream: false, response_format: { type: 'json_object' } });
  if (Buffer.byteLength(encoded) > maxBytes) throw fail('PERSONAL_REQUEST_TOO_LARGE');
  return encoded;
}

function serverFailure(status) {
  return fail(status === 401 || status === 403 ? 'PERSONAL_ACCESS_BLOCKED'
    : status === 429 ? 'PERSONAL_LIMIT_REACHED' : status >= 500 ? 'PERSONAL_SERVER_UNAVAILABLE' : 'PERSONAL_REQUEST_FAILED');
}

export function createPersonalModelClient({ provider, apiKey, fetchImpl = globalThis.fetch, timeoutMs = 10000,
  maxRequestBytes = 65536, maxResponseBytes = 65536 } = {}) {
  if (!Object.hasOwn(bases, provider) || typeof apiKey !== 'string' || !/^[\x21-\x7e]{8,4096}$/.test(apiKey)
      || typeof fetchImpl !== 'function') throw fail('PERSONAL_INVALID_CONFIGURATION');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000
      || [maxRequestBytes, maxResponseBytes].some(n => !Number.isInteger(n) || n < 1 || n > 1048576)) throw fail('PERSONAL_INVALID_LIMIT');

  return Object.freeze({ async chat(body, { signal } = {}) {
    if (signal !== undefined && (!(signal instanceof AbortSignal) || types.isProxy(signal))) throw fail('PERSONAL_INVALID_REQUEST');
    if (signal?.aborted) throw fail('PERSONAL_CANCELLED');
    const encoded = encodeBody(body, maxRequestBytes);
    const controller = new AbortController();
    let interrupted, interrupt, response, reader;
    const interruption = new Promise((_, reject) => {
      interrupt = code => {
        if (!interrupted) {
          interrupted = code; controller.abort();
          reader?.cancel().catch(() => {});
          reject(fail(code));
        }
      };
    });
    const cancel = () => interrupt('PERSONAL_CANCELLED');
    const timer = setTimeout(() => interrupt('PERSONAL_TIMEOUT'), timeoutMs);
    signal?.addEventListener('abort', cancel, { once: true });
    const url = `${bases[provider]}/chat/completions`;
    try {
      if (signal?.aborted) cancel();
      const operation = async () => {
        if (interrupted) throw fail(interrupted);
        response = await fetchImpl(url, { method: 'POST', redirect: 'manual', credentials: 'omit',
          headers: { authorization: `Bearer ${apiKey}`, accept: 'application/json', 'content-type': 'application/json' },
          body: encoded, signal: controller.signal });
        if (interrupted) {
          response?.body?.cancel?.().catch(() => {});
          throw fail(interrupted);
        }
        if (!response || !Number.isInteger(response.status) || response.status < 100 || response.status > 599) throw fail('PERSONAL_INVALID_RESPONSE');
        if (response.redirected || response.url && response.url !== url || response.status >= 300 && response.status < 400) throw fail('PERSONAL_REDIRECT_BLOCKED');
        if (response.status < 200 || response.status >= 300) throw serverFailure(response.status);
        const length = response.headers.get('content-length');
        if (length !== null && (!/^\d+$/.test(length) || !Number.isSafeInteger(Number(length)))) throw fail('PERSONAL_INVALID_RESPONSE');
        if (length !== null && Number(length) > maxResponseBytes) throw fail('PERSONAL_RESPONSE_TOO_LARGE');
        if (!/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '')) throw fail('PERSONAL_INVALID_CONTENT_TYPE');
        if (!response.body || typeof response.body.getReader !== 'function') throw fail('PERSONAL_INVALID_RESPONSE');
        const chunks = [];
        let total = 0;
        reader = response.body.getReader();
        for (;;) {
          const { value: chunk, done } = await reader.read();
          if (interrupted) throw fail(interrupted);
          if (done) break;
          if (!(chunk instanceof Uint8Array)) throw fail('PERSONAL_INVALID_RESPONSE');
          total += chunk.byteLength;
          if (total > maxResponseBytes) throw fail('PERSONAL_RESPONSE_TOO_LARGE');
          chunks.push(chunk);
        }
        let result;
        try { result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); }
        catch { throw fail('PERSONAL_INVALID_RESPONSE'); }
        if (result?.error) throw serverFailure(response.status);
        if (!record(result)) throw fail('PERSONAL_INVALID_RESPONSE');
        return result;
      };
      return await Promise.race([operation(), interruption]);
    } catch (error) {
      if (interrupted) throw fail(interrupted);
      if (error?.[ownError]) throw error;
      // Never forward upstream messages, bodies, headers, causes, or arbitrary exception codes.
      throw fail('PERSONAL_NETWORK_ERROR');
    } finally {
      clearTimeout(timer); signal?.removeEventListener('abort', cancel); controller.abort();
      if (reader) {
        reader.cancel().catch(() => {});
        try { reader.releaseLock(); } catch { /* A pending read retains its lock until cancellation settles. */ }
      }
      if (response?.body && !response.body.locked) response.body.cancel?.().catch(() => {});
    }
  } });
}
