const $ = id => document.getElementById(id);
const ui = Object.fromEntries(['refresh', 'cancel', 'connection', 'events-status', 'events', 'event-detail', 'consent', 'explain', 'result', 'feedback', 'app-name'].map(id => [id, $(id)]));
const labels = {
  disabled: '사용 안 함', personal: '개인 AI', disconnected: '엔진 미연결', demo: '예제', connected: '실제 연결',
  allow: '허용', allowed: '허용', deny: '거부', denied: '거부', block: '차단', blocked: '차단',
  active: '활성', inactive: '비활성', revoked: '철회됨', expired: '만료', valid: '유효', invalid: '유효하지 않음',
  trusted: '신뢰', untrusted: '신뢰하지 않음', healthy: '정상', unhealthy: '비정상', unknown: '확인 불가',
  pending: '대기 중', review: '검토 필요', suspended: '중지됨', terminated: '종료됨', isolated: '격리됨',
  compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', xdr: 'XDR 보안 이벤트',
  revoke_session: '세션 회수', isolate_device: '기기 격리', block_access: '접근 차단',
  openai: 'OpenAI', anthropic: 'Anthropic', xai: 'xAI', openrouter: 'OpenRouter', access: '접근', session: '세션', device: '기기',
};
let generation = 0;
let pending = null;
let status = null;
let events = [];
let selected = null;
let engineMode = null;
let available = true;

const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const text = (value, max = 10000) => typeof value === 'string' && value.length > 0 && value.length <= max;
const code = value => `${labels[value] || '서버 상태값'} (${value})`;
function node(tag, value, className) {
  const element = document.createElement(tag);
  if (value !== undefined) element.textContent = value;
  if (className) element.className = className;
  return element;
}
function feedback(message, error = false) {
  ui.feedback.textContent = message;
  ui.feedback.dataset.error = String(error);
}
function controls() {
  const busy = pending !== null;
  ui.refresh.disabled = busy || !available;
  ui.cancel.disabled = !busy;
  ui.consent.disabled = busy || !selected || !status || status.mode !== 'personal' || status.configured !== true || engineMode === 'disconnected' || !available;
  ui.explain.disabled = ui.consent.disabled || !ui.consent.checked;
  for (const button of ui.events.querySelectorAll('button')) button.disabled = busy;
}
function invalidate() {
  generation += 1;
  if (pending) { clearTimeout(pending.timer); pending.controller.abort(); }
  pending = null;
  controls();
}
function begin() {
  invalidate();
  const operation = { generation, controller: new AbortController(), timedOut: false, timer: null };
  operation.timer = setTimeout(() => {
    if (!current(operation)) return;
    operation.timedOut = true;
    operation.controller.abort();
    // Invalidate immediately even if a transport fails to honor abort.
    generation += 1;
    pending = null;
    feedback('15초 안에 응답을 받지 못했습니다. 요청을 중단했습니다. 결과가 확정되지 않았으므로 자동으로 다시 요청하지 않습니다.', true);
    ui.result.replaceChildren(node('p', '응답 대기 시간이 지났습니다. 뒤늦게 도착하는 응답은 표시하지 않습니다.'));
    if (!status) ui.connection.replaceChildren(node('p', '연결 상태를 확인하지 못했습니다. 상태를 다시 확인하세요.'));
    if (!engineMode) ui['events-status'].textContent = '보안 이벤트 목록을 확인하지 못했습니다. 빈 목록으로 판단하지 않습니다.';
    controls();
  }, 15000);
  pending = operation;
  controls();
  return operation;
}
const current = operation => available && pending === operation && generation === operation.generation;
function finish(operation) {
  clearTimeout(operation.timer);
  if (current(operation)) { pending = null; controls(); }
}
function failure(codeValue, message) {
  const error = new Error(message);
  error.code = codeValue;
  return error;
}
async function request(path, operation, body) {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST', credentials: 'omit', cache: 'no-store', redirect: 'error',
    signal: operation.controller.signal,
    ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  });
  const payload = await response.json().catch(() => { throw failure('INVALID_RESPONSE', '서버 응답을 확인할 수 없습니다.'); });
  if (!response.ok || payload?.ok !== true) {
    const errorCode = payload?.error?.code;
    throw failure(text(errorCode, 100) && /^[A-Z0-9_]+$/.test(errorCode) ? errorCode : 'REQUEST_FAILED',
      text(payload?.error?.message, 1000) ? payload.error.message : '요청에 실패했습니다. 상태를 다시 확인하세요.');
  }
  return payload.data;
}
function showFailure(error) {
  const errorLabels = { ENGINE_NOT_CONNECTED: '보안 엔진이 연결되지 않았습니다', INVALID_RESPONSE: '응답 형식 확인 필요', REQUEST_FAILED: '요청 실패', PERSONAL_AI_DISABLED: '개인 AI 사용 안 함', PERSONAL_AI_NOT_CONFIGURED: '개인 AI 설정 필요' };
  const id = error.code || 'NETWORK_ERROR';
  feedback(`${errorLabels[id] || '요청을 완료하지 못했습니다'} (${id}). ${error.code ? error.message : '서버 연결을 확인하세요.'} 자동으로 다시 시도하지 않습니다.`, true);
}
function facts(target, rows) {
  const dl = node('dl', undefined, 'facts');
  for (const [label, value] of rows) dl.append(node('dt', label), node('dd', value));
  target.append(dl);
}
function validStatus(data) {
  return record(data) && ['disabled', 'personal'].includes(data.mode) && typeof data.configured === 'boolean'
    && text(data.engineMode, 80) && data.automaticRetries === 0 && data.officialAssessment === false && data.executed === false
    && (data.provider === null || text(data.provider, 100)) && (data.requestedModel === null || text(data.requestedModel, 200));
}
function renderStatus(data) {
  ui.connection.replaceChildren();
  facts(ui.connection, [['AI 모드', code(data.mode)], ['연결 설정', data.configured ? '설정 존재 (configured: true) · 실제 AI 호출 성공은 아직 확인하지 않았습니다.' : '설정되지 않음 (configured: false)'],
    ['엔진 모드', code(data.engineMode)], ['공급자', data.provider ? (labels[data.provider] ? code(data.provider) : data.provider) : '설정 없음'],
    ['요청 모델', data.requestedModel || '설정 없음'], ['자동 재시도', '0회'], ['공식 평가·조치 실행', '해당 없음 · 실행하지 않음']]);
  const name = data.appName;
  if (text(name, 64) && [...name].length <= 32 && name === name.normalize('NFC') && name.trim() === name && !/[\p{Cc}\p{Cf}]/u.test(name)) {
    ui['app-name'].textContent = name;
    document.title = `개인 AI · ${name}`;
  }
}
function validItems(items) {
  return Array.isArray(items) && items.length <= 500 && items.every(item => record(item) && text(item.id, 200) && text(item.text)) && new Set(items.map(item => item.id)).size === items.length;
}
function validEvent(event) {
  return record(event) && text(event.id, 200) && text(event.kind, 100) && text(event.at, 100) && text(event.summary)
    && validItems(event.evidence) && validItems(event.rules) && record(event.state)
    && ['access', 'session', 'device'].every(key => text(event.state[key], 200))
    && Array.isArray(event.supportedActions) && event.supportedActions.length <= 20
    && event.supportedActions.every(action => text(action, 80))
    && new Set(event.supportedActions).size === event.supportedActions.length;
}
function renderEvents() {
  ui.events.replaceChildren();
  for (const event of events) {
    const button = node('button', undefined, 'event-button');
    button.type = 'button';
    button.setAttribute('aria-pressed', String(selected?.id === event.id));
    button.append(node('strong', event.summary), node('span', `${code(event.kind)} · ${event.at}`));
    button.addEventListener('click', () => selectEvent(event));
    ui.events.append(button);
  }
  controls();
}
function itemList(target, heading, items) {
  target.append(node('h3', heading));
  if (!items.length) { target.append(node('p', '기록 없음')); return; }
  const list = node('ul');
  for (const item of items) list.append(node('li', `[${item.id}] ${item.text}`));
  target.append(list);
}
function selectEvent(event) {
  invalidate();
  selected = event;
  ui.consent.checked = false;
  ui['event-detail'].replaceChildren(node('p', event.summary, 'summary'));
  facts(ui['event-detail'], [['보안 이벤트 ID', event.id], ['종류', code(event.kind)], ['시각', event.at], ['접근', code(event.state.access)], ['세션', code(event.state.session)], ['기기', code(event.state.device)]]);
  itemList(ui['event-detail'], '보안 이벤트 근거', event.evidence);
  itemList(ui['event-detail'], '관련 규칙', event.rules);
  ui.result.replaceChildren(node('p', '선택한 보안 이벤트에 대한 설명을 아직 요청하지 않았습니다.'));
  feedback('보안 이벤트 근거와 전송 안내를 확인한 뒤 설명을 요청하세요.');
  renderEvents();
}
async function load() {
  if (pending || !available) return;
  status = null; events = []; selected = null; engineMode = null;
  ui.consent.checked = false;
  ui.events.replaceChildren();
  ui.connection.replaceChildren(node('p', '상태 확인 중'));
  ui['event-detail'].replaceChildren(node('p', '목록에서 보안 이벤트 한 개를 선택하세요.', 'muted'));
  ui.result.replaceChildren(node('p', '아직 설명을 요청하지 않았습니다.'));
  ui['events-status'].textContent = '보안 이벤트 목록 확인 중';
  feedback('연결 상태와 보안 이벤트 목록을 확인하고 있습니다. AI 설명은 요청하지 않습니다.');
  const operation = begin();
  const results = await Promise.allSettled([request('/api/personal-ai/status', operation), request('/api/personal-ai/events', operation)]);
  if (!current(operation)) return;
  let error = null;
  if (results[0].status === 'fulfilled' && validStatus(results[0].value)) {
    status = results[0].value;
    renderStatus(status);
  } else {
    ui.connection.replaceChildren(node('p', '연결 상태를 확인하지 못했습니다.'));
    error = results[0].reason || failure('INVALID_RESPONSE', '개인 AI 상태 응답을 확인할 수 없습니다.');
  }
  const eventResult = results[1];
  if (eventResult.status === 'fulfilled') {
    const data = eventResult.value;
    if (!record(data) || !['disconnected', 'demo', 'connected'].includes(data.mode) || !Array.isArray(data.events) || data.events.length > 500 || !data.events.every(validEvent) || new Set(data.events.map(event => event.id)).size !== data.events.length) {
      error = failure('INVALID_RESPONSE', '보안 이벤트 목록 응답을 확인할 수 없습니다.');
      ui['events-status'].textContent = '보안 이벤트 목록 확인 실패';
    } else if (data.mode === 'disconnected') {
      engineMode = 'disconnected';
      ui['events-status'].textContent = '엔진 미연결 (disconnected). 정상적으로 조회된 빈 목록이 아닙니다.';
      error = failure('ENGINE_NOT_CONNECTED', '엔진을 연결한 뒤 상태를 다시 확인하세요.');
    } else {
      engineMode = data.mode;
      events = data.events;
      ui['events-status'].textContent = `${code(data.mode)} · ${events.length}개${data.mode === 'demo' ? ' · 예제이며 실제 보안 이벤트가 아닙니다.' : ''}${events.length === 0 ? ' · 정상 조회했으며 현재 표시할 보안 이벤트가 없습니다.' : ''}`;
      renderEvents();
    }
  } else {
    error = eventResult.reason;
    engineMode = error.code === 'ENGINE_NOT_CONNECTED' ? 'disconnected' : null;
    ui['events-status'].textContent = engineMode === 'disconnected' ? '엔진 미연결 (disconnected). 보안 이벤트 목록을 조회하지 못했습니다.' : '보안 이벤트 목록을 조회하지 못했습니다. 빈 목록으로 판단하지 않습니다.';
  }
  if (error) showFailure(error);
  else feedback(events.length ? '상태를 확인했습니다. 설명할 보안 이벤트 한 개를 선택하세요.' : '상태를 확인했습니다. 현재 표시할 보안 이벤트가 없습니다.');
  finish(operation);
}
function validExplanation(data, event) {
  const explanation = data?.explanation;
  const ids = new Set(event.evidence.map(item => item.id));
  const references = value => Array.isArray(value) && value.length > 0 && value.length <= ids.size
    && new Set(value).size === value.length && value.every(id => typeof id === 'string' && ids.has(id));
  return record(data) && data.mode === 'personal' && data.officialAssessment === false && data.executed === false && record(explanation)
    && text(explanation.summary) && references(explanation.evidenceIds) && explanation.evidenceIds.length === ids.size
    && explanation.requiresHumanConfirmation === true && explanation.executed === false
    && Array.isArray(explanation.proposals) && explanation.proposals.length <= 3
    && explanation.proposals.every(proposal => record(proposal) && event.supportedActions.includes(proposal.action) && text(proposal.reason) && references(proposal.evidenceIds))
    && text(data.requestedModel, 200) && text(data.responseModel, 200) && data.requestedModel === data.responseModel && (data.usage === null || record(data.usage))
    && Number.isFinite(data.latencyMs) && data.latencyMs >= 0;
}
function evidenceRefs(ids) { return ids.length ? ids.map(id => `[${id}]`).join(', ') : '참조 근거 없음'; }
async function explain() {
  if (pending || ui.explain.disabled || !selected || !ui.consent.checked) return;
  const event = selected;
  const operation = begin();
  ui.result.replaceChildren(node('p', '개인 AI에 선택한 보안 이벤트의 설명을 요청하고 있습니다.'));
  feedback('설명 요청 중입니다. 요청을 취소해도 공급자가 이미 처리한 사용량은 발생할 수 있습니다.');
  try {
    const data = await request('/api/personal-ai/explain', operation, { eventId: event.id });
    if (!current(operation) || selected !== event) return;
    if (!validExplanation(data, event)) throw failure('INVALID_RESPONSE', '설명 또는 근거 참조를 검증하지 못했습니다. 조치를 실행하지 않았습니다.');
    const explanation = data.explanation;
    ui.result.replaceChildren(node('p', explanation.summary, 'summary'), node('p', `설명 근거: ${evidenceRefs(explanation.evidenceIds)}`, 'muted'));
    ui.result.append(node('h3', '대응 제안 · 사람의 확인 필요'));
    if (!explanation.proposals.length) ui.result.append(node('p', '제시된 대응 제안이 없습니다.'));
    for (const proposal of explanation.proposals) {
      const box = node('div', undefined, 'proposal');
      box.append(node('strong', proposal.action), node('p', proposal.reason, 'summary'), node('p', `제안 근거: ${evidenceRefs(proposal.evidenceIds)}`, 'muted'));
      ui.result.append(box);
    }
    facts(ui.result, [['요청 모델', data.requestedModel], ['응답 모델', data.responseModel], ['응답 시간', `${data.latencyMs} ms`], ['공급자 보고 사용량', data.usage === null ? '보고되지 않음' : JSON.stringify(data.usage)], ['결과', '사람의 확인 필요 · 조치 실행 없음 · 공식 평가 아님']]);
    feedback('개인 AI 설명을 받았습니다. 실제 조치는 실행하지 않았습니다. 근거와 제안을 직접 검토하세요.');
    ui.consent.checked = false;
  } catch (error) {
    if (!current(operation)) return;
    ui.result.replaceChildren(node('p', '설명을 확인하지 못했습니다. 자동으로 다시 요청하지 않습니다.'));
    showFailure(error);
  } finally { finish(operation); }
}
ui.refresh.addEventListener('click', load);
ui.explain.addEventListener('click', explain);
ui.consent.addEventListener('change', controls);
ui.cancel.addEventListener('click', () => {
  invalidate();
  ui.consent.checked = false;
  if (!status) ui.connection.replaceChildren(node('p', '연결 상태 확인을 취소했습니다. 상태를 다시 확인하세요.'));
  if (!engineMode) ui['events-status'].textContent = '보안 이벤트 목록 확인을 취소했습니다. 빈 목록으로 판단하지 않습니다.';
  ui.result.replaceChildren(node('p', '요청을 취소했습니다. 뒤늦게 도착하는 응답은 표시하지 않습니다.'));
  feedback('요청을 취소했습니다. 공급자가 이미 처리한 사용량은 발생할 수 있습니다. 상태를 다시 확인할 수 있습니다.');
  controls();
});
addEventListener('pagehide', () => { available = false; invalidate(); ui.consent.checked = false; });
addEventListener('pageshow', event => {
  if (!event.persisted) return;
  available = true;
  invalidate();
  load();
});
load();
