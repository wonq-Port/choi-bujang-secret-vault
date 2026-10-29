<#
.SYNOPSIS
  내 PC의 C:\choi-bujang-secret-vault-main\on-client 폴더에 수정된 파일들을 한 번에 반영하는 자동 적용 스크립트
.DESCRIPTION
  웹 브라우저의 AI(Gemini)는 보안상 사용자 PC의 C: 드라이브에 직접 파일을 쓸 수 없으므로,
  이 스크립트를 실행하면 기존 파일을 .backup 으로 안전하게 보존한 뒤 수정본을 정확한 위치에 바로 넣어 줍니다.
#>
[CmdletBinding()]
param(
  [string]$ProjectRoot = "C:\choi-bujang-secret-vault-main",
  [switch]$IncludeServerTelemetry
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ProjectRoot)) {
  if (Test-Path -LiteralPath "C:\aleph-defense-starter-main\on-client") {
    $ProjectRoot = "C:\aleph-defense-starter-main"
  } else {
    throw "프로젝트 폴더($ProjectRoot)를 찾을 수 없습니다. 경로를 확인해 주세요."
  }
}

$OnClient = Join-Path $ProjectRoot "on-client"
if (-not (Test-Path -LiteralPath $OnClient)) {
  throw "$OnClient 폴더가 없습니다."
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " [복수를결심한인공능지] 내 PC 폴더 자동 반영 시작: $OnClient" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1. 기존 student/extension.mjs 백업 (처음 1회 보존)
$ExtTarget = Join-Path $OnClient "student\extension.mjs"
$ExtBackup = Join-Path $OnClient "student\extension.backup-original.mjs"
if ((Test-Path -LiteralPath $ExtTarget) -and -not (Test-Path -LiteralPath $ExtBackup)) {
  Copy-Item -LiteralPath $ExtTarget -Destination $ExtBackup -Force
  Write-Host "[원본 보존] student\extension.mjs -> student\extension.backup-original.mjs 백업 완료" -ForegroundColor Green
}

# 2. student/extension.mjs 반영
$ExtContent = @'
// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
function createBaseStudentView({ api, onChange } = {}) {
  let eventFilters = {
    kind: 'all',
    appId: 'all',
    access: 'all',
  };
  let selectedEventId = null;
  let internalEventUpdate = false;

  // 선택 기록 변경·새로고침 시 기존 AI 설명 및 조치 상태를 초기화·취소하고 늦게 도착한 응답 차단
  let explanationGeneration = 0;
  let activeExplanationEventId = null;
  let cancelledExplanationEventId = null;
  let clearedExplanationKey = null;
  let lastRenderedExplanationKey = null;

  let actionResetGeneration = 0;
  let activeActionEventId = null;
  let cancelledActionEventId = null;
  let clearedActionKey = null;
  let lastRenderedActionKey = null;

  const buildExplanationKey = (event, explanation, checkedAt) => {
    const evId = typeof event?.id === 'string' ? event.id.trim() : '';
    const st = typeof explanation?.status === 'string' ? explanation.status : '';
    const sum = typeof explanation?.data?.summary === 'string' ? explanation.data.summary : '';
    const errCode = typeof explanation?.error?.code === 'string' ? explanation.error.code : '';
    return `${evId}|${st}|${checkedAt ?? ''}|${sum}|${errCode}`;
  };

  const buildActionKey = (input = {}) => {
    const evId = typeof input?.event?.id === 'string' ? input.event.id.trim() : '';
    const st = typeof input?.status === 'string' ? input.status : '';
    const actId = typeof input?.actionId === 'string' ? input.actionId : '';
    const reqId = typeof input?.receipt?.requestId === 'string' ? input.receipt.requestId : '';
    const ver = input?.receipt?.version ?? '';
    const obsAt = typeof input?.observation?.observedAt === 'string' ? input.observation.observedAt : '';
    const eff = input?.observation?.effectApplied ?? '';
    const errCode = typeof input?.error?.code === 'string' ? input.error.code : '';
    return `${evId}|${st}|${actId}|${reqId}|${ver}|${obsAt}|${eff}|${errCode}`;
  };

  // 다른 기록을 선택하거나 목록을 다시 불러올 때 이전 AI 설명 및 조치 표시 상태를 함께 초기화·취소
  const resetSelectionLinkedStates = (nextEventId = null) => {
    explanationGeneration += 1;
    if (activeExplanationEventId && activeExplanationEventId !== nextEventId) {
      cancelledExplanationEventId = activeExplanationEventId;
    }
    activeExplanationEventId = nextEventId;
    if (lastRenderedExplanationKey) {
      clearedExplanationKey = lastRenderedExplanationKey;
    }

    actionResetGeneration += 1;
    if (activeActionEventId && activeActionEventId !== nextEventId) {
      cancelledActionEventId = activeActionEventId;
    }
    activeActionEventId = nextEventId;
    if (lastRenderedActionKey) {
      clearedActionKey = lastRenderedActionKey;
    }
  };

  const secretPattern = /(?:Bearer\s+\S+|sk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{8,}|github_pat_\S+|ac-on-[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_ -]?key|authorization|password|secret|token|비밀번호|토큰|열쇠)\s*[:=]\s*\S+)/i;

  const sanitizeText = (value, fallback = '확인 불가') => {
    if (typeof value !== 'string' || value.trim().length === 0) return fallback;
    if (secretPattern.test(value)) return '[보안상 민감정보 생략]';
    return value.trim();
  };

  const exactSemverPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

  const isExactSemver = (version) => {
    if (typeof version !== 'string' || version.length === 0 || version.length > 100 || secretPattern.test(version)) {
      return false;
    }
    const match = exactSemverPattern.exec(version.trim());
    if (!match) return false;
    const prerelease = match[4];
    if (prerelease) {
      for (const part of prerelease.split('.')) {
        if (!part || /^0\d+$/.test(part)) return false;
      }
    }
    return true;
  };

  return {
    renderIdentity({ me, devices, sessions } = {}) {
      const root = document.createElement('section');
      const addText = (parent, tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        parent.append(node);
        return node;
      };
      const valueText = (value) => typeof value === 'string' && value.length > 0 ? value : '확인 불가';
      const deviceLabels = {
        compliant: '보안 기준 충족',
        noncompliant: '보안 기준 미충족',
        unknown: '확인 불가',
      };
      const sessionLabels = {
        active: '활성',
        expired: '만료',
        revoked: '철회됨',
        unknown: '확인 불가',
      };
      const modeLabels = {
        connected: '연결됨',
        demo: '예제 자료',
        disconnected: '연결 없음',
        unknown: '확인 불가',
      };
      const modeLabel = (resource) => Object.hasOwn(modeLabels, resource?.mode)
        ? modeLabels[resource.mode]
        : modeLabels.unknown;
      const statusLabel = (status, labels) => Object.hasOwn(labels, status) ? labels[status] : '확인 불가';
      const section = (title) => {
        const block = document.createElement('section');
        addText(block, 'h3', title);
        root.append(block);
        return block;
      };
      const showMode = (block, resource) => {
        addText(block, 'p', `연결 상태: ${modeLabel(resource)}`);
      };
      const showResourceState = (block, title, resource, renderOk) => {
        const current = resource || {};
        if (current.status === 'loading') {
          addText(block, 'p', `${title}: 불러오는 중`);
        } else if (current.status === 'error') {
          const error = current.error || {};
          const message = valueText(error.message);
          const prefix = ['CONTRACT_MISMATCH', 'ENGINE_RESULT_UNVERIFIED'].includes(error.code)
            ? '확인 불가'
            : '연결 실패';
          addText(block, 'p', `${title}: ${prefix}: ${message}`);
        } else if (current.status === 'ok') {
          renderOk(block, current.data);
        } else {
          addText(block, 'p', `${title}: 확인 불가`);
        }
        showMode(block, current);
      };

      const account = section('현재 계정·기기·세션');
      showResourceState(account, '계정 정보', me, (block, data) => {
        const user = data?.user || {};
        const device = data?.device || {};
        const session = data?.session || {};
        addText(block, 'p', `사용자: ${valueText(user.label)} · ID: ${valueText(user.id)}`);
        addText(block, 'p', `현재 기기: ${valueText(device.label)} · ID: ${valueText(device.id)} · 상태: ${statusLabel(device.status, deviceLabels)}${Object.hasOwn(deviceLabels, device.status) ? ` (${device.status})` : ''}`);
        addText(block, 'p', `현재 세션: ID ${valueText(session.id)} · 상태: ${statusLabel(session.status, sessionLabels)}${Object.hasOwn(sessionLabels, session.status) ? ` (${session.status})` : ''}`);
      });

      const deviceList = section('기기 목록');
      showResourceState(deviceList, '기기 정보', devices, (block, data) => {
        if (!Array.isArray(data)) {
          addText(block, 'p', '기기 목록: 확인 불가');
          return;
        }
        const list = document.createElement('ul');
        for (const device of data) {
          const item = document.createElement('li');
          const status = statusLabel(device?.status, deviceLabels);
          const originalStatus = Object.hasOwn(deviceLabels, device?.status) ? ` (${device.status})` : '';
          item.textContent = `${valueText(device?.label)} · ID: ${valueText(device?.id)} · 상태: ${status}${originalStatus}`;
          list.append(item);
        }
        block.append(list);
      });

      const sessionList = section('세션 목록');
      showResourceState(sessionList, '세션 정보', sessions, (block, data) => {
        if (!Array.isArray(data)) {
          addText(block, 'p', '세션 목록: 확인 불가');
          return;
        }
        const list = document.createElement('ul');
        for (const session of data) {
          const item = document.createElement('li');
          const status = statusLabel(session?.status, sessionLabels);
          const originalStatus = Object.hasOwn(sessionLabels, session?.status) ? ` (${session.status})` : '';
          item.textContent = `ID: ${valueText(session?.id)} · 상태: ${status}${originalStatus}`;
          list.append(item);
        }
        block.append(list);
      });

      return root;
    },
    renderDecision({ status, mode, data, error, appId } = {}) {
      const root = document.createElement('section');
      const addText = (parent, tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        parent.append(node);
        return node;
      };
      const valueText = (value) => typeof value === 'string' && value.length > 0 ? value : '확인 불가';
      const modeLabels = {
        connected: '연결됨',
        demo: '예제 자료',
        disconnected: '연결 없음',
        unknown: '확인 불가',
      };
      const decisionLabels = {
        allow: '접근 허용(allow)',
        deny: '접근 거부(deny)',
        challenge: '추가 인증 또는 추가 확인 필요(challenge)',
        unknown: '판정 확인 불가(unknown)',
      };
      const decisionNotes = {
        allow: '정책상 접근 허용 판정입니다. 실제 앱 접속 성공을 보장하지는 않습니다.',
        deny: '정책상 접근 거부(차단) 판정입니다.',
        challenge: '추가 확인이 필요합니다. 이 화면은 추가 인증이나 확인 절차를 대신 수행하지 않습니다.',
        unknown: '판정을 확인할 수 없습니다(확인 불가). 허용되지 않음 상태이므로 정상이나 허용으로 간주하지 마세요.',
      };

      addText(root, 'h3', '업무 앱 접근 판정 결과');

      const targetAppId = typeof data?.appId === 'string' && data.appId.length > 0
        ? data.appId
        : (typeof appId === 'string' && appId.length > 0 ? appId : null);

      if (status === 'idle') {
        addText(root, 'p', '앱을 골라 접속을 요청하세요.');
      } else if (status === 'loading') {
        addText(root, 'p', targetAppId ? `판정 확인 중 · 앱 ID: ${targetAppId}` : '판정 확인 중');
      } else if (status === 'error') {
        const message = valueText(error?.message);
        const unverified = ['CONTRACT_MISMATCH', 'ENGINE_RESULT_UNVERIFIED'].includes(error?.code);
        if (targetAppId) {
          addText(root, 'p', `대상 앱 ID: ${targetAppId}`);
        }
        addText(root, 'p', unverified ? `요청 실패 (확인 불가): ${message}` : `요청 실패: ${message}`);
        addText(root, 'p', '요청 자체가 실패하여 판정을 확인하지 못했습니다. 이는 접근 거부(deny) 판정이 아니며, 접근이 허용되지 않음 상태입니다.');
      } else if (status === 'ok') {
        const rawDecision = data?.decision;
        const normalizedDecision = Object.hasOwn(decisionLabels, rawDecision) ? rawDecision : 'unknown';
        addText(root, 'p', `대상 앱 ID: ${valueText(targetAppId)}`);
        addText(root, 'p', `판정 결과: ${decisionLabels[normalizedDecision]}`);
        addText(root, 'p', decisionNotes[normalizedDecision]);
        addText(root, 'p', `판정 이유: ${valueText(data?.reason)}`);
        addText(root, 'p', `판정 시각: ${valueText(data?.checkedAt)}`);
      } else {
        addText(root, 'p', '판정 확인 불가(unknown): 허용되지 않음');
      }

      if (mode !== null && mode !== undefined) {
        const modeText = Object.hasOwn(modeLabels, mode) ? modeLabels[mode] : modeLabels.unknown;
        addText(root, 'p', `연결 상태: ${modeText}`);
      }

      return root;
    },
    renderEvents({ status, mode, data, error } = {}) {
      if (!internalEventUpdate) {
        eventFilters = { kind: 'all', appId: 'all', access: 'all' };
        selectedEventId = null;
        resetSelectionLinkedStates(null);
      }

      const root = document.createElement('section');
      const addText = (parent, tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        parent.append(node);
        return node;
      };
      const valueText = (value) => typeof value === 'string' && value.length > 0 ? value : '확인 불가';
      const modeLabels = {
        connected: '연결됨',
        demo: '예제 자료',
        disconnected: '연결 없음',
        unknown: '확인 불가',
      };
      const kindLabels = {
        access: '접속 기록(access)',
        xdr: 'XDR 경보(xdr)',
      };
      const accessLabels = {
        allowed: '허용됨(allowed)',
        denied: '거부됨(denied)',
        unknown: '확인 불가(unknown)',
      };
      const sessionLabels = {
        active: '활성(active)',
        expired: '만료(expired)',
        revoked: '철회됨(revoked)',
        unknown: '확인 불가(unknown)',
      };
      const deviceLabels = {
        compliant: '보안 기준 충족(compliant)',
        noncompliant: '보안 기준 미충족(noncompliant)',
        unknown: '확인 불가(unknown)',
      };

      const kindText = (kind) => Object.hasOwn(kindLabels, kind) ? kindLabels[kind] : '확인 불가(unknown)';
      const stateText = (value, labels) => Object.hasOwn(labels, value) ? labels[value] : '확인 불가(unknown)';
      const appText = (appId) => typeof appId === 'string' && appId.length > 0 ? appId : '앱 ID 확인 불가(없음)';

      addText(root, 'h3', '내 접속 기록 및 XDR 보안 경보');

      if (mode !== null && mode !== undefined) {
        const modeText = Object.hasOwn(modeLabels, mode) ? modeLabels[mode] : modeLabels.unknown;
        addText(root, 'p', `연결 상태: ${modeText}`);
      }

      if (status === 'loading') {
        eventFilters = { kind: 'all', appId: 'all', access: 'all' };
        selectedEventId = null;
        resetSelectionLinkedStates(null);
        addText(root, 'p', '보안 기록을 불러오는 중입니다.');
        return root;
      }

      if (status === 'error') {
        eventFilters = { kind: 'all', appId: 'all', access: 'all' };
        selectedEventId = null;
        resetSelectionLinkedStates(null);
        const message = valueText(error?.message);
        const unverified = ['CONTRACT_MISMATCH', 'ENGINE_RESULT_UNVERIFIED'].includes(error?.code);
        addText(
          root,
          'p',
          unverified
            ? `기록을 불러오지 못했습니다 (확인 불가): ${message}`
            : `기록을 불러오지 못했습니다: ${message}`,
        );
        addText(root, 'p', '조회 실패 또는 응답 확인 불가 상태입니다. 기록이 없는 정상 빈 목록이 아닙니다.');
        return root;
      }

      if (status !== 'ok' || !Array.isArray(data)) {
        eventFilters = { kind: 'all', appId: 'all', access: 'all' };
        selectedEventId = null;
        resetSelectionLinkedStates(null);
        addText(root, 'p', '기록을 불러오지 못했습니다 (확인 불가): 응답 데이터를 확인할 수 없습니다.');
        return root;
      }

      const sortedEvents = [...data].sort((a, b) => {
        const timeA = Date.parse(a?.at ?? '');
        const timeB = Date.parse(b?.at ?? '');
        if (Number.isFinite(timeA) && Number.isFinite(timeB) && timeA !== timeB) {
          return timeB - timeA;
        }
        return String(b?.at ?? '').localeCompare(String(a?.at ?? ''));
      });

      const filterBar = document.createElement('div');
      const buildSelect = (labelText, options, currentValue, onSelectChange) => {
        const label = document.createElement('label');
        label.textContent = `${labelText} `;
        const select = document.createElement('select');
        select.setAttribute('aria-label', labelText);
        for (const opt of options) {
          const optionNode = document.createElement('option');
          optionNode.value = opt.value;
          optionNode.textContent = opt.label;
          if (opt.value === currentValue) {
            optionNode.selected = true;
          }
          select.append(optionNode);
        }
        select.value = options.some((opt) => opt.value === currentValue) ? currentValue : 'all';
        select.addEventListener('change', () => {
          onSelectChange(select.value);
        });
        label.append(select);
        filterBar.append(label);
        return select;
      };

      const kindValues = ['access', 'xdr'];
      for (const ev of sortedEvents) {
        if (typeof ev?.kind === 'string' && ev.kind.length > 0 && !kindValues.includes(ev.kind)) {
          kindValues.push(ev.kind);
        }
      }
      const kindOptions = [
        { value: 'all', label: '전체(all)' },
        ...kindValues.map((k) => ({ value: k, label: kindText(k) })),
      ];

      const appValues = [];
      for (const ev of sortedEvents) {
        if (typeof ev?.appId === 'string' && ev.appId.length > 0 && !appValues.includes(ev.appId)) {
          appValues.push(ev.appId);
        }
      }
      const appOptions = [
        { value: 'all', label: '전체(all)' },
        ...appValues.map((app) => ({ value: app, label: app })),
      ];

      const accessValues = ['allowed', 'denied', 'unknown'];
      for (const ev of sortedEvents) {
        const accessVal = ev?.state?.access;
        if (typeof accessVal === 'string' && accessVal.length > 0 && !accessValues.includes(accessVal)) {
          accessValues.push(accessVal);
        }
      }
      const accessOptions = [
        { value: 'all', label: '전체(all)' },
        ...accessValues.map((acc) => ({ value: acc, label: stateText(acc, accessLabels) })),
      ];

      const contentContainer = document.createElement('div');

      const notifyChange = () => {
        if (typeof onChange === 'function') {
          internalEventUpdate = true;
          try {
            onChange();
          } finally {
            internalEventUpdate = false;
          }
        }
      };

      const renderFilteredContent = () => {
        while (contentContainer.firstChild) {
          contentContainer.removeChild(contentContainer.firstChild);
        }

        if (sortedEvents.length === 0) {
          selectedEventId = null;
          addText(contentContainer, 'p', '표시할 기록이 없습니다.');
          return;
        }

        const filteredEvents = sortedEvents.filter((ev) => {
          if (eventFilters.kind !== 'all' && ev?.kind !== eventFilters.kind) return false;
          if (eventFilters.appId !== 'all' && ev?.appId !== eventFilters.appId) return false;
          if (eventFilters.access !== 'all' && ev?.state?.access !== eventFilters.access) return false;
          return true;
        });

        addText(contentContainer, 'p', `표시 건수: ${filteredEvents.length}건 / 전체 ${sortedEvents.length}건`);

        if (filteredEvents.length === 0) {
          addText(contentContainer, 'p', '표시할 기록이 없습니다.');
        } else {
          const list = document.createElement('ul');
          for (const ev of filteredEvents) {
            const item = document.createElement('li');
            const eventId = valueText(ev?.id);
            item.setAttribute('data-student-event-id', eventId);

            const rowText = document.createElement('span');
            rowText.textContent = `사건 ID: ${eventId} · 시각: ${valueText(ev?.at)} · 종류: ${kindText(ev?.kind)} · 앱: ${appText(ev?.appId)} · 요약: ${valueText(ev?.summary)} `;
            item.append(rowText);

            const detailBtn = document.createElement('button');
            detailBtn.type = 'button';
            detailBtn.textContent = `${eventId} 상세`;
            detailBtn.setAttribute('aria-label', `${eventId} 상세`);
            detailBtn.addEventListener('click', () => {
              // 다른 기록을 선택할 때 기존 AI 설명 및 조치 상태를 초기화·취소하여 이전 표시가 남지 않게 처리
              if (selectedEventId !== eventId) {
                resetSelectionLinkedStates(eventId);
              }
              selectedEventId = eventId;
              renderFilteredContent();
              notifyChange();
            });
            item.append(detailBtn);
            list.append(item);
          }
          contentContainer.append(list);
        }

        const selectedEvent = selectedEventId
          ? filteredEvents.find((ev) => ev?.id === selectedEventId)
          : null;

        if (selectedEventId && !selectedEvent) {
          // 필터 변경으로 현재 선택했던 기록이 목록에서 제외된 경우 설명·조치 상태도 함께 초기화
          resetSelectionLinkedStates(null);
        }

        if (selectedEvent) {
          const detailBox = document.createElement('section');
          const detailId = valueText(selectedEvent.id);
          detailBox.setAttribute('data-student-event-detail', detailId);

          addText(detailBox, 'h4', `기록 상세: ${detailId}`);
          addText(detailBox, 'p', `사건 ID: ${detailId}`);
          addText(detailBox, 'p', `발생 시각: ${valueText(selectedEvent.at)}`);
          addText(detailBox, 'p', `기록 종류: ${kindText(selectedEvent.kind)}`);
          addText(detailBox, 'p', `업무 앱(appId): ${appText(selectedEvent.appId)}`);
          addText(detailBox, 'p', `요약: ${valueText(selectedEvent.summary)}`);

          const eventState = selectedEvent.state || {};
          addText(detailBox, 'p', `접속 상태(state.access): ${stateText(eventState.access, accessLabels)}`);
          addText(detailBox, 'p', `세션 상태(state.session): ${stateText(eventState.session, sessionLabels)}`);
          addText(detailBox, 'p', `기기 상태(state.device): ${stateText(eventState.device, deviceLabels)}`);

          addText(detailBox, 'h5', '근거(evidence)');
          const evidenceList = document.createElement('ul');
          if (Array.isArray(selectedEvent.evidence) && selectedEvent.evidence.length > 0) {
            for (const evItem of selectedEvent.evidence) {
              addText(evidenceList, 'li', `${valueText(evItem?.id)}: ${valueText(evItem?.text)}`);
            }
          } else {
            addText(evidenceList, 'li', '근거 정보 없음');
          }
          detailBox.append(evidenceList);

          addText(detailBox, 'h5', '규칙(rules)');
          const rulesList = document.createElement('ul');
          if (Array.isArray(selectedEvent.rules) && selectedEvent.rules.length > 0) {
            for (const ruleItem of selectedEvent.rules) {
              addText(rulesList, 'li', `${valueText(ruleItem?.id)}: ${valueText(ruleItem?.text)}`);
            }
          } else {
            addText(rulesList, 'li', '규칙 정보 없음');
          }
          detailBox.append(rulesList);

          const actions = Array.isArray(selectedEvent.supportedActions)
            ? selectedEvent.supportedActions.filter((act) => typeof act === 'string' && act.trim().length > 0)
            : [];
          if (actions.length > 0) {
            const actionBox = document.createElement('div');
            addText(
              actionBox,
              'p',
              '조치 실행 연결은 준비 중입니다. 아직 지원하지 않는 조치이며, 요청을 보내지 않고 실행되지도 않았습니다(조치 미지원·미실행).',
            );
            for (const act of actions) {
              const actionName = act.trim();
              const actionBtn = document.createElement('button');
              actionBtn.type = 'button';
              actionBtn.disabled = true;
              actionBtn.setAttribute('aria-disabled', 'true');
              actionBtn.textContent = `${actionName} 미지원`;
              actionBtn.setAttribute('aria-label', `${actionName} 미지원`);
              actionBox.append(actionBtn);
            }
            detailBox.append(actionBox);
          }

          contentContainer.append(detailBox);
        }
      };

      buildSelect('기록 종류', kindOptions, eventFilters.kind, (val) => {
        eventFilters.kind = val;
        renderFilteredContent();
        notifyChange();
      });
      buildSelect('업무 앱', appOptions, eventFilters.appId, (val) => {
        eventFilters.appId = val;
        renderFilteredContent();
        notifyChange();
      });
      buildSelect('접속 상태', accessOptions, eventFilters.access, (val) => {
        eventFilters.access = val;
        renderFilteredContent();
        notifyChange();
      });

      root.append(filterBar);
      renderFilteredContent();
      root.append(contentContainer);

      return root;
    },
    renderStatus({ devices, sessions, notifications, diagnostics, mode } = {}) {
      const root = document.createElement('section');
      const addText = (parent, tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        parent.append(node);
        return node;
      };
      const section = (title) => {
        const block = document.createElement('section');
        addText(block, 'h4', title);
        root.append(block);
        return block;
      };

      const modeLabels = {
        connected: '연결됨(connected)',
        demo: '예제 자료(demo)',
        disconnected: '연결 없음(disconnected)',
        unknown: '확인 불가(unknown)',
      };
      const deviceLabels = {
        compliant: '보안 기준 충족(compliant) · 정상',
        noncompliant: '보안 기준 미충족(noncompliant) · 점검 필요(정상 아님)',
        unknown: '확인 불가(unknown) · 점검 필요(정상 아님)',
      };
      const sessionLabels = {
        active: '활성(active) · 정상',
        expired: '만료(expired) · 종료된 세션(주의 필요·정상 아님)',
        revoked: '철회됨(revoked) · 회수된 세션(주의 필요·정상 아님)',
        unknown: '확인 불가(unknown) · 주의 필요(정상 아님)',
      };
      const resourceLabels = {
        me: '로그인 정보(me)',
        apps: '업무 앱(apps)',
        events: '보안 기록(events)',
        devices: '기기(devices)',
        sessions: '세션(sessions)',
        access: '접속 판정(access)',
        diagnostics: '도움정보(diagnostics)',
        vulnerabilities: '설치 패키지 조회(vulnerabilities)',
      };

      const isTimeoutError = (err) => {
        const code = String(err?.code ?? '');
        const msg = String(err?.message ?? '');
        return /TIMEOUT/i.test(code) || /시간\s*초과|초과됐습니다|timeout/i.test(msg);
      };

      const formatErrorLine = (targetLabel, err) => {
        const msg = sanitizeText(err?.message, '오류 메시지를 확인할 수 없습니다.');
        const code = sanitizeText(err?.code, 'UNKNOWN_ERROR');
        if (isTimeoutError(err)) {
          return `${targetLabel}를 불러오지 못했습니다 (응답 시간 초과 · ${code}): ${msg}`;
        }
        if (['CONTRACT_MISMATCH', 'ENGINE_RESULT_UNVERIFIED'].includes(err?.code)) {
          return `${targetLabel}를 불러오지 못했습니다 (응답 형식 확인 불가 · ${code}): ${msg}`;
        }
        return `${targetLabel}를 불러오지 못했습니다 (${code}): ${msg}`;
      };

      addText(root, 'h3', '보호 현황 · 기기·세션·알림·진단 정보');
      const currentModeText = Object.hasOwn(modeLabels, mode) ? modeLabels[mode] : modeLabels.unknown;
      addText(root, 'p', `현재 연결 상태: ${currentModeText}`);

      // 1. 등록 기기 상태 (devices)
      const deviceBlock = section('등록 기기 상태');
      addText(deviceBlock, 'p', '내 이름으로 등록되고 회수되지 않은 기기(최대 100대, 지금 쓰는 기기 우선)를 표시합니다.');
      if (devices?.status === 'loading') {
        addText(deviceBlock, 'p', '기기 정보를 불러오는 중입니다.');
      } else if (devices?.status === 'error') {
        addText(deviceBlock, 'p', formatErrorLine('기기 정보', devices.error));
        addText(deviceBlock, 'p', '자동으로 다시 요청하지 않습니다. 다시 시도는 위쪽 다시 불러오기 버튼을 직접 누르세요.');
      } else if (devices?.status === 'ok') {
        if (!Array.isArray(devices.data)) {
          addText(deviceBlock, 'p', '기기 정보를 불러오지 못했습니다 (확인 불가): 기기 목록 형식을 확인할 수 없습니다. 다시 시도는 위쪽 다시 불러오기 버튼을 직접 누르세요.');
        } else if (devices.data.length === 0) {
          addText(deviceBlock, 'p', '등록된 기기가 없습니다. (조회 성공 · 빈 목록이며 오류가 아닙니다.)');
        } else {
          const list = document.createElement('ul');
          for (const dev of devices.data) {
            const label = sanitizeText(dev?.label, '이름 확인 불가');
            const id = sanitizeText(dev?.id, 'ID 확인 불가');
            const statusText = Object.hasOwn(deviceLabels, dev?.status)
              ? deviceLabels[dev.status]
              : deviceLabels.unknown;
            addText(list, 'li', `기기: ${label} · ID: ${id} · 상태: ${statusText}`);
          }
          deviceBlock.append(list);
        }
      } else {
        addText(deviceBlock, 'p', '기기 정보를 불러오지 못했습니다 (확인 불가). 다시 시도는 위쪽 다시 불러오기 버튼을 직접 누르세요.');
      }

      // 2. 현재 연결 세션 상태 (sessions)
      const sessionBlock = section('현재 연결 세션 상태');
      addText(sessionBlock, 'p', '세션은 지금 검증된 현재 연결 하나만 표시합니다. 과거의 연결 이력이나 다른 기기 세션 전체가 아닙니다.');
      if (sessions?.status === 'loading') {
        addText(sessionBlock, 'p', '현재 연결 세션 정보를 불러오는 중입니다.');
      } else if (sessions?.status === 'error') {
        addText(sessionBlock, 'p', formatErrorLine('세션 정보', sessions.error));
        addText(sessionBlock, 'p', '자동으로 다시 요청하지 않습니다. 다시 시도는 위쪽 다시 불러오기 버튼을 직접 누르세요.');
      } else if (sessions?.status === 'ok') {
        if (!Array.isArray(sessions.data)) {
          addText(sessionBlock, 'p', '세션 정보를 불러오지 못했습니다 (확인 불가): 세션 데이터 형식을 확인할 수 없습니다. 다시 시도는 위쪽 다시 불러오기 버튼을 직접 누르세요.');
        } else if (sessions.data.length === 0) {
          addText(sessionBlock, 'p', '현재 연결 없음 (현재 검증된 연결 세션이 없습니다 · 빈 상태이며 조회 오류가 아닙니다.)');
        } else {
          const list = document.createElement('ul');
          for (const sess of sessions.data) {
            const id = sanitizeText(sess?.id, 'ID 확인 불가');
            const statusText = Object.hasOwn(sessionLabels, sess?.status)
              ? sessionLabels[sess.status]
              : sessionLabels.unknown;
            addText(list, 'li', `현재 연결 세션 ID: ${id} · 상태: ${statusText}`);
          }
          sessionBlock.append(list);
        }
      } else {
        addText(sessionBlock, 'p', '현재 연결 세션 정보를 불러오지 못했습니다 (확인 불가). 다시 시도는 위쪽 다시 불러오기 버튼을 직접 누르세요.');
      }

      // 3. 주의 알림 목록 (notifications)
      const notifBlock = section('주의 알림');
      if (!Array.isArray(notifications) || notifications.length === 0) {
        addText(notifBlock, 'p', '주의할 알림이 없습니다 (알림 없음).');
      } else {
        addText(
          notifBlock,
          'p',
          '점검이 필요한 항목이나 조회 실패 알림이 있습니다. 자동으로 재시도하지 않으므로 연결 상태를 확인한 뒤 위쪽 다시 불러오기 버튼을 직접 누르거나 도움정보를 복사해 문의하세요.',
        );
        const list = document.createElement('ul');
        for (const item of notifications) {
          const rawResource = sanitizeText(item?.resource, 'unknown');
          const resourceName = Object.hasOwn(resourceLabels, rawResource)
            ? resourceLabels[rawResource]
            : `자료(${rawResource})`;
          const safeCode = sanitizeText(item?.code, 'UNVERIFIED');
          const safeMsg = sanitizeText(item?.message, '알림 내용을 확인할 수 없습니다.');
          addText(list, 'li', `자료: ${resourceName} · 코드(code): ${safeCode} · 내용: ${safeMsg}`);
        }
        notifBlock.append(list);
      }

      // 4. 진단 정보 (diagnostics) 및 도움정보 복사 버튼
      const diagBlock = section('진단 정보 (도움정보)');
      addText(
        diagBlock,
        'p',
        '이 진단 정보는 강사·담당자에게 도움 요청을 보낼 때 쓰도록 안전한 항목(requestId·component·version·checkedAt·engine.mode·engine.code)만 표시하고 복사합니다. 비밀번호·토큰·API 키는 화면에 표시하거나 복사하지 않으며, 사용자가 버튼을 누를 때만 복사합니다.',
      );

      let safeCopyPayload = '';

      if (diagnostics?.status === 'loading') {
        addText(diagBlock, 'p', '진단 정보(도움정보)를 불러오는 중입니다.');
      } else if (diagnostics?.status === 'error') {
        addText(diagBlock, 'p', formatErrorLine('진단 정보(도움정보)', diagnostics.error));
        addText(diagBlock, 'p', '자동으로 다시 요청하지 않습니다. 다시 시도는 위쪽 도움정보 불러오기 또는 다시 불러오기 버튼을 직접 누르세요.');
      } else if (diagnostics?.status === 'ok' && diagnostics.data && typeof diagnostics.data === 'object') {
        const d = diagnostics.data;
        const safeFields = {
          requestId: sanitizeText(d.requestId),
          component: sanitizeText(d.component),
          version: sanitizeText(d.version),
          checkedAt: sanitizeText(d.checkedAt),
          engineMode: sanitizeText(d.engine?.mode),
          engineCode: sanitizeText(d.engine?.code),
        };
        const diagList = document.createElement('ul');
        addText(diagList, 'li', `requestId: ${safeFields.requestId}`);
        addText(diagList, 'li', `component: ${safeFields.component}`);
        addText(diagList, 'li', `version: ${safeFields.version}`);
        addText(diagList, 'li', `checkedAt: ${safeFields.checkedAt}`);
        addText(diagList, 'li', `engine.mode: ${safeFields.engineMode}`);
        addText(diagList, 'li', `engine.code: ${safeFields.engineCode}`);
        diagBlock.append(diagList);

        safeCopyPayload = [
          `requestId: ${safeFields.requestId}`,
          `component: ${safeFields.component}`,
          `version: ${safeFields.version}`,
          `checkedAt: ${safeFields.checkedAt}`,
          `engine.mode: ${safeFields.engineMode}`,
          `engine.code: ${safeFields.engineCode}`,
        ].join('\n');
      } else {
        addText(diagBlock, 'p', '아직 진단 정보(도움정보)를 불러오지 않았습니다. 위쪽 도움정보 불러오기 버튼을 눌러 조회하세요.');
      }

      const copyBtn = document.createElement('button');
      copyBtn.type = 'button';
      copyBtn.textContent = '도움정보 복사';
      copyBtn.setAttribute('aria-label', '도움정보 복사');
      copyBtn.disabled = !safeCopyPayload;
      if (!safeCopyPayload) {
        copyBtn.setAttribute('aria-disabled', 'true');
      }

      const copyStatus = document.createElement('p');
      copyStatus.textContent = safeCopyPayload
        ? '도움정보 복사 버튼을 누르면 위의 안전한 진단 항목만 복사됩니다.'
        : '진단 정보가 준비되면 도움정보 복사 버튼을 사용할 수 있습니다.';

      copyBtn.addEventListener('click', () => {
        if (!safeCopyPayload) return;
        try {
          if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            Promise.resolve(navigator.clipboard.writeText(safeCopyPayload)).catch(() => {});
          }
        } catch {
          // 클립보드 API 예외 무시
        }
        copyStatus.textContent = `도움 요청용 안전한 진단 정보를 복사했습니다 (${safeCopyPayload.replace(/\n/g, ' · ')}).`;
      });

      diagBlock.append(copyBtn);
      diagBlock.append(copyStatus);

      return root;
    },
    renderAiConnection({ status, mode, data, error, checkedAt, explanationAccepted } = {}) {
      const root = document.createElement('section');
      const addText = (parent, tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        parent.append(node);
        return node;
      };
      const modeLabels = {
        connected: '연결됨(connected)',
        demo: '예제 자료(demo · 실제 게이트 수용 아님)',
        disconnected: '연결 없음(disconnected)',
        unknown: '확인 불가(unknown)',
      };

      const describeAiError = (rawCode, rawMessage) => {
        const code = sanitizeText(rawCode, 'AI_REQUEST_UNVERIFIED');
        const msg = sanitizeText(rawMessage, 'AI 연결 또는 응답을 확인할 수 없습니다.');

        if (code === 'ON_AI_PROVISIONING_PENDING' || code === 'ON_AI_AUTHORIZATION_CHANGED' || code === 'SUBJECT_SCOPE_UNVERIFIED' || code === 'AI_REQUEST_UNVERIFIED') {
          return {
            code,
            msg,
            category: '권한 준비 중·확인 불가',
            guide: '학생 앱 이용 권한의 발급·연결을 준비 중이거나 확인할 수 없습니다(학생 코드 잘못이 아님). 담당자에게 계정 연결과 앱 권한 확인을 요청하세요. 연결 완료가 아니므로 성공으로 처리하지 않습니다.',
          };
        }
        if (code === 'WB_CLCO_AUTH_REQUIRED' || /AUTH/i.test(code)) {
          return {
            code,
            msg,
            category: '인증 실패',
            guide: '앱 전용 인증을 확인하지 못했습니다. 계정 연결을 다시 확인하고 담당자에게 문의하세요. Workbench 열쇠나 외부 API 키를 복사해 넣지 마세요. (연결 성공이 아닙니다.)',
          };
        }
        if (code === 'WB_CLCO_ACCESS_BLOCKED' || /BLOCKED|FORBIDDEN/i.test(code)) {
          return {
            code,
            msg,
            category: '접근 제한',
            guide: '학생 앱의 이용 권한이 제한되어 있습니다. 계정 연결을 다시 확인하고 담당자에게 앱 권한 설정을 확인하세요. (연결 성공이 아닙니다.)',
          };
        }
        if (code === 'WB_CLCO_COHORT_BUDGET_EXHAUSTED' || code === 'WB_CLCO_LIMIT_REACHED' || /BUDGET|LIMIT|QUOTA/i.test(code)) {
          return {
            code,
            msg,
            category: '사용량·한도 초과',
            guide: '반의 AI 사용량이 소진되었거나 AI 이용 한도에 도달했습니다. 담당자에게 사용량 및 한도를 확인하세요.',
          };
        }
        if (code === 'WB_CLCO_SESSION_CLOSED' || /SESSION_CLOSED/i.test(code)) {
          return {
            code,
            msg,
            category: '이용 시간 아님',
            guide: '현재 AI 이용 가능 시간이 아닙니다. 운영 이용 시간을 확인하세요.',
          };
        }
        if (code === 'WB_CLCO_CANCELLED' || code === 'CANCELLED' || code === 'REQUEST_CANCELLED' || /CANCEL/i.test(code)) {
          return {
            code,
            msg,
            category: '취소',
            guide: 'AI 연결 점검 요청이 취소되었습니다(취소됨). 이전 응답은 현재 결과가 아니며 연결 성공으로 간주하지 않습니다. 필요하면 사용자가 직접 다시 점검 버튼을 누르세요.',
          };
        }
        if (code === 'ON_AI_MODEL_LIST_EMPTY' || code === 'MODEL_NOT_CONFIGURED' || /MODEL/i.test(code)) {
          return {
            code,
            msg,
            category: '모델 없음',
            guide: '현재 앱 권한으로 쓸 수 있는 AI 모델이 없습니다. 담당자에게 모델 허용 설정 확인을 요청하세요.',
          };
        }
        if (code === 'WB_CLCO_RATE_LIMITED' || code === 'WB_CLCO_TIMEOUT' || code === 'REQUEST_TIMEOUT' || code === 'ENGINE_TIMEOUT' || code === 'TIMEOUT' || /TIMEOUT|RATE_LIMIT/i.test(code) || /초과|제한/i.test(msg)) {
          const isTimeout = /TIMEOUT/i.test(code) || /초과/i.test(msg);
          return {
            code,
            msg,
            category: isTimeout ? '요청 제한·시간 초과·네트워크 (응답 시간 초과)' : '요청 제한·시간 초과·네트워크',
            guide: isTimeout
              ? 'AI 응답 시간이 초과됐습니다(시간 초과). 자동으로 다시 점검하지 않으므로 잠시 뒤 사용자가 직접 다시 점검 버튼을 누르세요. (연결 성공이 아닙니다.)'
              : 'AI 요청이 잠시 제한되었거나 네트워크 지연이 발생했습니다. 자동으로 다시 점검하지 않으므로 잠시 뒤 사용자가 직접 다시 점검 버튼을 누르세요.',
          };
        }
        return {
          code,
          msg,
          category: '확인 불가',
          guide: 'AI 연결 상태를 확인할 수 없습니다. 계정 연결을 다시 확인하거나 담당자에게 문의하세요. 자동으로 다시 점검하지 않으므로 필요하면 사용자가 직접 버튼을 눌러 다시 점검하세요.',
        };
      };

      addText(root, 'h3', '앱 내부 AI 연결 상태 점검');

      if (mode !== null && mode !== undefined) {
        const modeText = Object.hasOwn(modeLabels, mode) ? modeLabels[mode] : modeLabels.unknown;
        addText(root, 'p', `연결 모드: ${modeText}`);
      }

      if (status === 'idle' || !status) {
        addText(root, 'p', 'AI 연결 점검 전입니다. 계정 연결이나 설정이 바뀌면 이전 점검 결과는 유지되지 않으며, 점검은 사용자가 직접 「현재 API 연결 점검」 버튼을 눌러 실행합니다.');
        addText(root, 'p', '사건 설명은 아직 실행하지 않았습니다.');
        return root;
      }

      if (status === 'loading') {
        addText(root, 'p', 'AI 연결 점검 중입니다. 현재 로그인과 앱 권한으로 AI 모델 응답을 확인하고 있습니다.');
        addText(root, 'p', '사건 설명은 아직 실행하지 않았습니다.');
        return root;
      }

      if (status === 'error') {
        const info = describeAiError(error?.code, error?.message);
        addText(root, 'p', `AI 연결 점검 실패 · 오류 코드(code): ${info.code}`);
        addText(root, 'p', `오류 안내(message): ${info.msg}`);
        addText(root, 'p', `원인 구분: ${info.category} — ${info.guide}`);
        addText(root, 'p', '자동으로 다시 점검하지 않습니다. 다시 점검은 사용자가 직접 버튼을 눌러 실행하세요.');
        return root;
      }

      if (status === 'ok' && data && typeof data === 'object') {
        const authMode = data.audienceAuthorization;
        const authLabel = authMode === 'test'
          ? '시험 연결 점검(test)'
          : authMode === 'verified'
            ? '앱 권한 확인 후 점검(verified)'
            : '확인 불가(unknown)';
        const modelCountText = Number.isInteger(data.modelCount) ? `${data.modelCount}개` : sanitizeText(String(data.modelCount ?? ''), '확인 불가');
        const checkedAtText = sanitizeText(checkedAt ?? data.checkedAt, '확인 불가');

        addText(root, 'p', `점검 구분: ${authLabel}`);
        addText(root, 'p', `응답 모델 수(modelCount): ${modelCountText}`);
        addText(root, 'p', `점검 시각(checkedAt): ${checkedAtText}`);
        if (data.help && typeof data.help === 'object') {
          addText(
            root,
            'p',
            `점검 상세 코드: ${sanitizeText(data.help.code)} · 권한 상태(provisioning): ${sanitizeText(data.help.provisioning)}`,
          );
        }
        addText(
          root,
          'p',
          explanationAccepted === true
            ? '선택한 사건의 AI 설명 응답이 확인되었습니다.'
            : '이 점검은 AI 연결과 모델 목록 응답만 확인했으며, 사건 설명은 아직 실행하지 않았습니다. 모델 목록 응답만으로 사건 설명이 완료된 것이 아니므로 보안 기록에서 따로 요청하고 확인하세요.',
        );
        addText(root, 'p', '자동으로 다시 점검하지 않습니다. 다시 점검은 사용자가 직접 버튼을 눌러 실행하세요.');
        return root;
      }

      addText(root, 'p', 'AI 연결 점검 결과를 확인할 수 없습니다(확인 불가). 다시 점검은 사용자가 직접 버튼을 눌러 실행하세요.');
      return root;
    },
    renderExplanation({ event, explanation, checkedAt } = {}) {
      const root = document.createElement('section');
      const addText = (parent, tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        parent.append(node);
        return node;
      };

      const accessLabels = {
        allowed: '허용됨(allowed)',
        denied: '거부됨(denied)',
        unknown: '확인 불가(unknown)',
      };
      const sessionLabels = {
        active: '활성(active)',
        expired: '만료(expired)',
        revoked: '철회됨(revoked)',
        unknown: '확인 불가(unknown)',
      };
      const deviceLabels = {
        compliant: '보안 기준 충족(compliant)',
        noncompliant: '보안 기준 미충족(noncompliant)',
        unknown: '확인 불가(unknown)',
      };
      const stateLabel = (val, map) => Object.hasOwn(map, val) ? map[val] : '확인 불가(unknown)';

      addText(root, 'h3', 'AI 사건 설명');

      const status = explanation?.status;
      const hasValidEventId = Boolean(event && typeof event === 'object' && typeof event.id === 'string' && event.id.trim().length > 0);
      const eventId = hasValidEventId ? sanitizeText(event.id, '') : '';
      const currentKey = buildExplanationKey(event, explanation, checkedAt);

      // 다른 기록을 선택했거나 새로고침으로 초기화된 이전 설명·늦게 도착한 이전 사건 응답 차단
      if (hasValidEventId) {
        if (!internalEventUpdate && status === 'loading' && selectedEventId === null) {
          if (activeExplanationEventId && activeExplanationEventId !== eventId) {
            cancelledExplanationEventId = activeExplanationEventId;
          }
          activeExplanationEventId = eventId;
          clearedExplanationKey = null;
        }

        const switchedInEventsList = selectedEventId !== null && selectedEventId !== eventId;
        const switchedActiveEvent = activeExplanationEventId !== null && activeExplanationEventId !== eventId;
        const isCancelledStaleEvent = cancelledExplanationEventId !== null
          && cancelledExplanationEventId === eventId
          && selectedEventId !== null
          && selectedEventId !== eventId;
        const isClearedSnapshot = clearedExplanationKey !== null && currentKey === clearedExplanationKey;

        if (switchedInEventsList || switchedActiveEvent || isCancelledStaleEvent || isClearedSnapshot) {
          const targetId = selectedEventId || activeExplanationEventId || '새 기록';
          addText(
            root,
            'p',
            `선택한 보안 기록이 변경(${targetId})되었거나 새로고침되어 이전 사건(${eventId})의 AI 설명을 초기화·취소했습니다. 늦게 도착한 이전 사건의 응답은 새 기록에 붙지 않습니다.`,
          );
          addText(root, 'p', '현재 선택한 보안 기록에 대해 AI 설명을 새로 요청하세요. 기록은 그대로입니다.');
          return root;
        }
      }

      // 1) explanation.status가 error이면 event가 null이어도 안전한 오류 코드·메시지와 실패 이유를 먼저 표시
      if (status === 'error') {
        lastRenderedExplanationKey = currentKey;
        const safeCode = sanitizeText(explanation?.error?.code, 'AI_REQUEST_UNVERIFIED');
        const safeMsg = sanitizeText(explanation?.error?.message, 'AI 설명을 불러오지 못했습니다.');
        if (eventId) {
          addText(root, 'p', `사건 ID: ${eventId}`);
        }
        addText(root, 'p', `AI 설명 실패 (${safeCode}): ${safeMsg}`);
        if (safeCode === 'ON_AI_INVALID_INPUT') {
          addText(root, 'p', '사건 설명에 필요한 근거(evidence) 또는 규칙(rules)이 부족하거나 확인할 수 없어 설명을 생성하지 못했습니다. 근거가 없으면 내용을 지어내지 않습니다.');
        } else if (safeCode === 'ON_AI_INVALID_OUTPUT') {
          addText(root, 'p', 'AI 응답의 인용 근거 ID가 사건 근거와 맞지 않거나 이미 실행되었다고 답한 잘못된 형식이어서 이 설명을 사용할 수 없습니다.');
        }
        addText(root, 'p', '기록은 그대로입니다. AI 설명이 실패해도 기존 보안 기록과 업무 앱 판정은 그대로 유지됩니다.');
        return root;
      }

      // 오류 없이 event만 null인 경우 보안 기록을 먼저 선택하도록 안내
      if (!hasValidEventId) {
        addText(root, 'p', '보안 기록에서 기록을 먼저 고르세요. (아직 선택된 사건이 없습니다.)');
        return root;
      }

      if (status === 'loading') {
        activeExplanationEventId = eventId;
        lastRenderedExplanationKey = currentKey;
        addText(root, 'p', `사건 ID: ${eventId} · 선택한 기록의 AI 설명을 요청하는 중입니다 (요청 세대 #${explanationGeneration}).`);
        return root;
      }

      if (status === 'ok' && explanation?.data && typeof explanation.data === 'object') {
        const expData = explanation.data;
        const summary = sanitizeText(expData.summary, '');

        // 이미 실행되었다고 답한 설명(executed: true) 또는 사람 확인 누락 거부
        if (expData.executed === true || expData.requiresHumanConfirmation === false) {
          addText(root, 'p', `사건 ID: ${eventId}`);
          addText(
            root,
            'p',
            'AI 설명 실패 (ON_AI_INVALID_OUTPUT): AI가 조치를 이미 실행했다고 답했거나 사람 확인 조건이 누락된 설명이므로 사용할 수 없습니다. 조치는 자동 실행되지 않으며 기록은 그대로입니다.',
          );
          return root;
        }

        if (!summary) {
          addText(root, 'p', `사건 ID: ${eventId}`);
          addText(root, 'p', 'AI 설명 실패 (ON_AI_INVALID_OUTPUT): 설명 요약(summary)을 확인할 수 없어 사용할 수 없습니다. 기록은 그대로입니다.');
          return root;
        }

        // 사건 자체의 근거(evidence) 또는 규칙(rules) 부족 확인
        const rawEvidence = Array.isArray(event.evidence) ? event.evidence : [];
        const rawRules = Array.isArray(event.rules) ? event.rules : [];
        if (rawEvidence.length === 0 || rawRules.length === 0) {
          addText(root, 'p', `사건 ID: ${eventId}`);
          addText(
            root,
            'p',
            'AI 설명 실패 (ON_AI_INVALID_INPUT): 설명에 필요한 사건 근거(evidence)나 규칙(rules)이 부족하여 설명을 사용할 수 없습니다. 없는 근거를 지어내지 않으며 기록은 그대로입니다.',
          );
          return root;
        }

        const evidenceMap = new Map();
        for (const item of rawEvidence) {
          if (item && typeof item.id === 'string' && item.id.trim().length > 0 && typeof item.text === 'string' && item.text.trim().length > 0) {
            evidenceMap.set(item.id.trim(), item.text.trim());
          }
        }
        if (evidenceMap.size === 0 || evidenceMap.size !== rawEvidence.length) {
          addText(root, 'p', `사건 ID: ${eventId}`);
          addText(
            root,
            'p',
            'AI 설명 실패 (ON_AI_INVALID_INPUT): 사건 근거(evidence) 형식이 올바르지 않아 설명을 사용할 수 없습니다. 기록은 그대로입니다.',
          );
          return root;
        }

        // 다른 사건 ID가 지정된 응답 거부
        if (typeof expData.eventId === 'string' && expData.eventId.trim().length > 0 && expData.eventId.trim() !== eventId) {
          addText(root, 'p', `사건 ID: ${eventId}`);
          addText(
            root,
            'p',
            'AI 설명 실패 (ON_AI_INVALID_OUTPUT): 다른 사건에 대한 설명 응답이므로 현재 기록에 사용할 수 없습니다. 기록은 그대로입니다.',
          );
          return root;
        }

        // evidenceIds와 현재 event.evidence의 id 대조 (없는 ID·중복·누락 거부)
        const citedIds = Array.isArray(expData.evidenceIds)
          ? expData.evidenceIds.filter((id) => typeof id === 'string' && id.trim().length > 0).map((id) => id.trim())
          : [];
        const uniqueCited = new Set(citedIds);
        const evidenceMatched = citedIds.length > 0
          && uniqueCited.size === citedIds.length
          && citedIds.length === evidenceMap.size
          && citedIds.every((id) => evidenceMap.has(id));

        if (!evidenceMatched) {
          addText(root, 'p', `사건 ID: ${eventId}`);
          addText(
            root,
            'p',
            'AI 설명 실패 (ON_AI_INVALID_OUTPUT): 인용한 근거 ID가 현재 기록의 근거(event.evidence)와 맞지 않아 그 설명을 쓸 수 없습니다(근거가 맞지 않음). 없는 근거를 지어내지 않으며 기록은 그대로입니다.',
          );
          return root;
        }

        // proposals 정합성 확인
        const rawProposals = Array.isArray(expData.proposals) ? expData.proposals : [];
        const supportedActions = Array.isArray(event.supportedActions)
          ? event.supportedActions.filter((a) => typeof a === 'string' && a.trim().length > 0).map((a) => a.trim())
          : [];
        const proposalsValid = rawProposals.every((p) => {
          if (!p || typeof p !== 'object') return false;
          const act = typeof p.action === 'string' ? p.action.trim() : '';
          const rsn = typeof p.reason === 'string' ? p.reason.trim() : '';
          const pEvIds = Array.isArray(p.evidenceIds) ? p.evidenceIds : [];
          if (!act || !rsn || pEvIds.length === 0) return false;
          if (!supportedActions.includes(act)) return false;
          return pEvIds.every((id) => typeof id === 'string' && evidenceMap.has(id.trim()));
        });

        if (!proposalsValid) {
          addText(root, 'p', `사건 ID: ${eventId}`);
          addText(
            root,
            'p',
            'AI 설명 실패 (ON_AI_INVALID_OUTPUT): 제안된 조치(proposals)나 제안 근거 ID가 현재 기록이 지원하는 조치·근거와 맞지 않아 그 설명을 쓸 수 없습니다. 기록은 그대로입니다.',
          );
          return root;
        }

        activeExplanationEventId = eventId;
        lastRenderedExplanationKey = currentKey;

        // 2) 성공한 설명에만 data-student-explanation-event=event.id 지정
        root.setAttribute('data-student-explanation-event', eventId);

        addText(root, 'h4', 'AI 설명(참고용)');
        addText(root, 'p', `사건 ID: ${eventId}`);
        addText(
          root,
          'p',
          '이 설명은 AI가 선택한 기록의 근거·규칙을 읽고 작성한 참고용 해석입니다. 사실 판단은 인용한 근거와 연동 시스템(원천)이 알려 준 현재 상태를 기준으로 하세요.',
        );
        addText(root, 'p', `AI 요약: ${summary}`);
        if (checkedAt) {
          addText(root, 'p', `확인 시각: ${sanitizeText(checkedAt)}`);
        }

        // 3) evidenceIds를 event.evidence와 대조해 "근거 ID — 근거 글" 표시
        addText(root, 'h5', '인용한 근거(evidence)');
        const evidenceList = document.createElement('ul');
        for (const refId of citedIds) {
          const evText = sanitizeText(evidenceMap.get(refId), '');
          addText(evidenceList, 'li', `${refId} — ${evText}`);
        }
        root.append(evidenceList);

        // 규칙(event.rules)을 "규칙 ID — 규칙 글"로 표시
        addText(root, 'h5', '적용 규칙(rules)');
        const rulesList = document.createElement('ul');
        for (const rule of rawRules) {
          const rId = sanitizeText(rule?.id, '확인 불가');
          const rText = sanitizeText(rule?.text, '확인 불가');
          addText(rulesList, 'li', `${rId} — ${rText}`);
        }
        root.append(rulesList);

        // 4) 현재 상태 및 unknown(확인 불가) 항목 구분 표시
        const st = event.state || {};
        addText(root, 'h5', '현재 상태(state)');
        const stateList = document.createElement('ul');
        addText(stateList, 'li', `접속(access): ${stateLabel(st.access, accessLabels)}`);
        addText(stateList, 'li', `세션(session): ${stateLabel(st.session, sessionLabels)}`);
        addText(stateList, 'li', `기기(device): ${stateLabel(st.device, deviceLabels)}`);
        root.append(stateList);

        addText(root, 'h5', '확인되지 않은 현재 상태(unknown)');
        const unknownItems = [];
        if (!Object.hasOwn(accessLabels, st.access) || st.access === 'unknown') {
          unknownItems.push('접속: 확인 불가(unknown) — 상태를 확인할 수 없으므로 정상·안전으로 간주하지 마세요.');
        }
        if (!Object.hasOwn(sessionLabels, st.session) || st.session === 'unknown') {
          unknownItems.push('세션: 확인 불가(unknown) — 상태를 확인할 수 없으므로 정상·안전으로 간주하지 마세요.');
        }
        if (!Object.hasOwn(deviceLabels, st.device) || st.device === 'unknown') {
          unknownItems.push('기기: 확인 불가(unknown) — 상태를 확인할 수 없으므로 정상·안전으로 간주하지 마세요.');
        }
        if (unknownItems.length === 0) {
          addText(root, 'p', '없음');
        } else {
          const unknownList = document.createElement('ul');
          for (const uText of unknownItems) {
            addText(unknownList, 'li', uText);
          }
          root.append(unknownList);
        }

        // 5 & 6) 조치 제안(proposals) 및 미실행 상태 표시 (실행 버튼 없음)
        addText(root, 'h5', '조치 제안(proposals)');
        if (rawProposals.length === 0) {
          if (supportedActions.length === 0) {
            addText(
              root,
              'p',
              '연동 시스템(원천)이 지원하는 조치가 없어 제안이 없습니다(정상). 설명·제안만으로 보안 조치가 실행되지 않았습니다.',
            );
          } else {
            addText(
              root,
              'p',
              'AI가 제안한 조치가 없습니다. 필요하면 인용한 근거를 확인하고 담당자와 판단하세요. 보안 조치는 실행되지 않았습니다.',
            );
          }
        } else {
          const proposalList = document.createElement('ul');
          for (const prop of rawProposals) {
            const act = sanitizeText(prop.action);
            const rsn = sanitizeText(prop.reason);
            const refs = prop.evidenceIds.map((id) => sanitizeText(id)).join(', ');
            addText(
              proposalList,
              'li',
              `${act} — 이유: ${rsn} (인용 근거 ID: ${refs}) · 사람 확인이 필요하며 실행되지 않았습니다(미실행).`,
            );
          }
          root.append(proposalList);
        }

        return root;
      }

      addText(root, 'p', `사건 ID: ${eventId} · 아직 AI 설명을 요청하지 않았습니다. 보안 기록에서 AI 설명 요청 버튼을 직접 누르세요.`);
      return root;
    },
    renderAction(input = {}) {
      const {
        status,
        event,
        actionId,
        target,
        receipt,
        observation,
        message,
        confirmationExpiresAt,
        error,
      } = input || {};

      const root = document.createElement('section');
      const addText = (parent, tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        parent.append(node);
        return node;
      };

      addText(root, 'h3', '보안 조치 요청 상태 및 실제 처리 결과');
      addText(
        root,
        'p',
        '학생 화면은 조치 버튼을 직접 만들거나 확인 티켓·POST 요청을 보내지 않습니다. 제공 화면의 조치 준비·사람 확인·결과 재조회·취소 버튼을 사용하세요.',
      );

      const hasEventId = Boolean(event && typeof event === 'object' && typeof event.id === 'string' && event.id.trim().length > 0);
      const eventId = hasEventId ? sanitizeText(event.id, '') : '';
      const currentKey = buildActionKey(input);

      // 다른 기록 선택 또는 목록 새로고침 시 이전 조치 표시를 초기화하고 늦은 응답 차단 (action_refresh)
      if (hasEventId && status && status !== 'idle') {
        if (!internalEventUpdate && (status === 'loading' || status === 'prepared') && selectedEventId === null) {
          if (activeActionEventId && activeActionEventId !== eventId) {
            cancelledActionEventId = activeActionEventId;
          }
          activeActionEventId = eventId;
          clearedActionKey = null;
        }

        const switchedInEventsList = selectedEventId !== null && selectedEventId !== eventId;
        const switchedActiveAction = activeActionEventId !== null && activeActionEventId !== eventId;
        const isCancelledStaleAction = cancelledActionEventId !== null
          && cancelledActionEventId === eventId
          && selectedEventId !== null
          && selectedEventId !== eventId;
        const isClearedActionSnapshot = clearedActionKey !== null && currentKey === clearedActionKey;

        if (switchedInEventsList || switchedActiveAction || isCancelledStaleAction || isClearedActionSnapshot) {
          const nextTargetId = selectedEventId || activeActionEventId || '새 기록';
          addText(
            root,
            'p',
            `조치 상태: 아직 미실행(idle) — 선택한 보안 기록이 변경(${nextTargetId})되었거나 새로고침되어 이전 사건(${eventId})의 조치 표시를 지우고 초기화했습니다(세대 #${actionResetGeneration}).`,
          );
          addText(
            root,
            'p',
            '화면을 초기화해도 이미 서버에 전달된 요청이 있다면 그 효과가 저절로 취소되지는 않으므로 필요하면 결과를 별도로 확인하세요.',
          );
          return root;
        }
      }

      if (!status || status === 'idle') {
        addText(root, 'p', '조치 상태: 아직 미실행(idle) — 아직 준비하거나 요청한 보안 조치가 없습니다. AI의 조치 제안만으로 조치가 실행되지 않습니다.');
        if (message) {
          addText(root, 'p', `안내: ${sanitizeText(message)}`);
        }
        addText(root, 'p', '현재 기록의 지원 조치(supportedActions)가 비어 있으면 조치 준비 버튼이 표시되지 않는 것이 정상입니다.');
        return root;
      }

      // receipt가 있을 때 현재 사건(event.id) 및 조치(actionId)와의 정합성 확인 (current_intent_binding)
      const receiptEventId = typeof receipt?.eventId === 'string' && receipt.eventId.trim().length > 0 ? sanitizeText(receipt.eventId, '') : '';
      const receiptActionId = typeof receipt?.actionId === 'string' && receipt.actionId.trim().length > 0 ? sanitizeText(receipt.actionId, '') : '';
      const resolvedActionId = typeof actionId === 'string' && actionId.trim().length > 0 ? sanitizeText(actionId, '') : receiptActionId;

      if ((eventId && receiptEventId && eventId !== receiptEventId) || (resolvedActionId && receiptActionId && resolvedActionId !== receiptActionId)) {
        addText(
          root,
          'p',
          '조치 상태: 요청 처리 안 됨(error) · 사건 또는 조치 ID가 현재 선택된 의도(intent)와 일치하지 않아 이전 결과를 표시하지 않습니다(완료 아님·미실행). 현재 사건에서 다시 준비하세요.',
        );
        return root;
      }

      const resolvedEventId = eventId || receiptEventId;
      const requestId = typeof receipt?.requestId === 'string' && receipt.requestId.trim().length > 0
        ? sanitizeText(receipt.requestId, '')
        : '';
      const receiptId = typeof receipt?.receiptId === 'string' && receipt.receiptId.trim().length > 0
        ? sanitizeText(receipt.receiptId, '')
        : '';
      const versionText = Number.isSafeInteger(receipt?.version)
        ? String(receipt.version)
        : (typeof receipt?.version === 'string' && receipt.version.trim().length > 0 ? sanitizeText(receipt.version, '') : '');

      if (resolvedEventId) {
        activeActionEventId = resolvedEventId;
      }
      lastRenderedActionKey = currentKey;

      // 성공적으로 그린 바깥 요소에 data-student-action-event와 data-student-action-request 부착
      if (resolvedEventId) {
        root.setAttribute('data-student-action-event', resolvedEventId);
      }
      if (requestId) {
        root.setAttribute('data-student-action-request', requestId);
      }

      // 상태별 표시 문구 분기
      if (status === 'loading') {
        addText(
          root,
          'p',
          '조치 상태: 조치 준비 또는 결과 조회 중(loading) — 연동 시스템(원천)에 조치 준비 정보나 처리 결과를 확인하고 있습니다. 아직 완료되지 않았으며 실행 성공이 아닙니다(완료 아님).',
        );
      } else if (status === 'prepared') {
        addText(
          root,
          'p',
          '조치 상태: 준비됨·미실행(prepared) — 조치 대상과 확인 기한만 준비된 상태이며 아직 서버에 집행을 요청하지 않았습니다(미실행·완료 아님).',
        );
        addText(
          root,
          'p',
          '사건 ID·근거 ID·조치·실제 대상과 확인 기한을 직접 확인한 뒤, 기한 안에 제공 화면의 「대상과 조치를 확인했으며 집행합니다」 버튼을 눌러야 실제 요청이 전송됩니다.',
        );
      } else if (status === 'executing') {
        addText(
          root,
          'p',
          '조치 상태: 서버에 전달 중(executing) — 사람 확인 후 서버에 조치 요청을 전송하고 있습니다. 아직 결과가 없으며 처리 완료나 성공이 아닙니다(완료 아님).',
        );
      } else if (status === 'pending') {
        addText(
          root,
          'p',
          '조치 상태: 서버 접수·처리 중(pending) — 서버가 요청을 접수(ACK)하여 처리 중입니다. 서버가 받았다는 접수 응답(ACK)은 실제 조치 효과가 적용되었다는 뜻이 아니며 아직 완료되지 않았습니다(완료 아님). 제공 화면의 「연동 시스템 결과만 재조회」 버튼으로 실제 효과를 확인하세요.',
        );
      } else if (status === 'succeeded') {
        const effectVerified = Boolean(
          observation
          && typeof observation === 'object'
          && observation.effectApplied === true
          && typeof observation.observedAt === 'string'
          && observation.observedAt.trim().length > 0,
        );
        if (effectVerified) {
          addText(
            root,
            'p',
            '조치 상태: 효과 확인(succeeded) — 연동 시스템(원천)에서 실제 보안 조치 효과 적용이 확인되었습니다.',
          );
          addText(
            root,
            'p',
            `원천 관측 시각(observedAt): ${sanitizeText(observation.observedAt)} · 실제 효과 적용 여부: effectApplied: true`,
          );
        } else {
          // observation.effectApplied === true가 아니면 성공으로 표시하지 않고 결과 불명으로 처리
          addText(
            root,
            'p',
            '조치 상태: 결과 불명(unknown) — 원천의 실제 효과 적용(observation.effectApplied: true)이 확인되지 않아 성공으로 인정하지 않습니다(효과 없음으로 판단 금지 · 완료 아님). 제공 화면의 결과 재조회 버튼으로 결과만 다시 확인하세요.',
          );
        }
      } else if (status === 'denied') {
        const denyMsg = sanitizeText(error?.message || message, '현재 연동 시스템 정책이 이 조치를 허용하지 않습니다.');
        addText(root, 'p', `조치 상태: 거절(denied) — 연동 시스템(원천)이 조치를 거절했습니다(미적용): ${denyMsg}`);
      } else if (status === 'failed') {
        const failMsg = sanitizeText(error?.message || message, '연동 시스템에서 조치 처리에 실패했습니다.');
        addText(root, 'p', `조치 상태: 실패(failed) — 연동 시스템(원천) 처리 실패(미적용): ${failMsg}`);
      } else if (status === 'unknown') {
        const unknownMsg = sanitizeText(
          error?.message || message,
          '조치 결과를 아직 확인할 수 없습니다.',
        );
        addText(
          root,
          'p',
          `조치 상태: 결과 불명(unknown) · 효과 없음으로 판단 금지 — ${unknownMsg} 성공이나 효과 없음으로 단정하지 말고, 중복 집행 없이 제공 화면의 「연동 시스템 결과만 재조회」 버튼으로 결과만 재조회하세요.`,
        );
      } else if (status === 'expired') {
        const expMsg = sanitizeText(
          error?.message || message,
          '사람 확인 기한이 지났습니다.',
        );
        addText(
          root,
          'p',
          `조치 상태: 확인 기한 지남(expired) · 다시 준비 필요 — ${expMsg} 이번 준비로는 집행할 수 없으며 조치는 실행되지 않았습니다(미실행). 현재 사건에서 제공 화면의 「조치 준비」 버튼으로 다시 준비하세요.`,
        );
      } else if (status === 'error') {
        const safeCode = sanitizeText(error?.code, 'ACTION_RESULT_UNVERIFIED');
        const safeMsg = sanitizeText(error?.message || message, '요청이 처리되지 않았습니다.');
        addText(
          root,
          'p',
          `조치 상태: 요청 처리 안 됨(error) · 오류 코드(code): ${safeCode} — ${safeMsg} (실행 성공 아님)`,
        );
      } else {
        addText(
          root,
          'p',
          '조치 상태: 결과 불명(unknown) · 효과 없음으로 판단 금지 — 알 수 없는 상태이므로 성공이나 효과 없음으로 단정하지 말고 결과만 재조회하세요.',
        );
      }

      // 전달받은 범위의 상세 식별 정보 표시
      const detailList = document.createElement('ul');
      if (resolvedEventId) {
        addText(detailList, 'li', `사건 ID(event.id): ${resolvedEventId}`);
      }
      if (Array.isArray(event?.evidence) && event.evidence.length > 0) {
        const evIds = event.evidence
          .map((ev) => (typeof ev?.id === 'string' && ev.id.trim().length > 0 ? sanitizeText(ev.id, '') : ''))
          .filter(Boolean);
        if (evIds.length > 0) {
          addText(detailList, 'li', `근거 ID(event.evidence): ${evIds.join(', ')}`);
        }
      }
      if (resolvedActionId) {
        addText(detailList, 'li', `조치 ID(actionId): ${resolvedActionId}`);
      }
      if (target && typeof target === 'object') {
        if (typeof target.id === 'string' && target.id.trim().length > 0) {
          addText(detailList, 'li', `실제 대상 ID(target.id): ${sanitizeText(target.id)}`);
        }
        if (target.generation !== undefined && target.generation !== null) {
          addText(detailList, 'li', `대상 세대(target.generation): ${String(target.generation)}`);
        }
      }
      if (typeof confirmationExpiresAt === 'string' && confirmationExpiresAt.trim().length > 0) {
        addText(detailList, 'li', `확인 기한(confirmationExpiresAt): ${sanitizeText(confirmationExpiresAt)}`);
      }
      if (requestId) {
        addText(detailList, 'li', `요청 ID(receipt.requestId): ${requestId}`);
      }
      if (receiptId) {
        addText(detailList, 'li', `접수 영수증 ID(receipt.receiptId): ${receiptId}`);
      }
      if (versionText) {
        addText(detailList, 'li', `버전(receipt.version): ${versionText}`);
      }
      if (typeof receipt?.replayed === 'boolean') {
        addText(
          detailList,
          'li',
          `중복 요청 여부(receipt.replayed): ${String(receipt.replayed)}${receipt.replayed ? ' (이미 접수된 동일 요청 재응답 · 중복 실행 방지됨)' : ''}`,
        );
      }
      if (receipt?.superseded === true) {
        addText(detailList, 'li', '이전 조회 대체 여부(superseded): true — 이전 조회는 최신 결과를 대신하지 않습니다.');
      }
      if (observation && typeof observation === 'object') {
        if (typeof observation.observedAt === 'string' && observation.observedAt.trim().length > 0) {
          addText(detailList, 'li', `관측 시각(observation.observedAt): ${sanitizeText(observation.observedAt)}`);
        }
        if (typeof observation.effectApplied === 'boolean') {
          addText(detailList, 'li', `효과 적용 여부(observation.effectApplied): effectApplied: ${String(observation.effectApplied)}`);
        }
      }
      if (error && typeof error === 'object' && status !== 'error') {
        const errCode = sanitizeText(error.code, '');
        const errMsg = sanitizeText(error.message, '');
        if (errCode || errMsg) {
          addText(detailList, 'li', `오류 정보: ${errCode ? `${errCode}: ` : ''}${errMsg}`);
        }
      }

      if (detailList.firstChild) {
        root.append(detailList);
      }

      return root;
    },
    renderVulnerabilities({ status, mode, data, error } = {}) {
      const root = document.createElement('section');
      const addText = (parent, tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        parent.append(node);
        return node;
      };

      const modeLabels = {
        connected: '연결됨(connected)',
        demo: '예제 자료(demo)',
        disconnected: '연결 없음(disconnected)',
        unknown: '확인 불가(unknown)',
      };

      const scanStatusLabels = {
        complete: '모두 조회(complete)',
        partial: '일부 조회 실패(partial)',
        not_checked: '아직 조회 안 함(not_checked)',
        not_configured: '조회 준비 미완료(not_configured)',
        unverifiable: 'lock 파일 확인 불가(unverifiable)',
      };

      const scanStatusNotes = {
        complete: '프로젝트의 package-lock.json과 실제 설치된 node_modules 메타데이터를 대조하여 허용된 공개 패키지의 정확한 설치 버전을 OSV에 모두 조회했습니다.',
        partial: '일부 결과(partial): 허용된 패키지 중 일부 패키지의 OSV 조회가 실패하여 전체 조회를 완료하지 못했습니다. 이미 확인된 취약점 ID는 지우지 않고 보존하며, 조회하지 못한 패키지는 확인 불가(unverifiable)로 표시합니다(모두 안전·취약점 없음 아님).',
        not_checked: '아직 조회하지 않았습니다(not_checked): 승인된 공개 조회 대상 패키지가 없어 외부 OSV 조회를 수행하지 않았습니다. 미조회 상태는 취약점 없음·정상·안전이 아닙니다.',
        not_configured: '조회 준비 미완료·미설정 상태(not_configured): 프로젝트 경로 또는 승인 목록이 아직 설정되지 않아 조회를 실행하지 못했습니다. 설정 안 됨 상태는 취약점 없음·정상·안전이 아닙니다.',
        unverifiable: '설치 목록(lock 파일) 확인 불가(unverifiable): package-lock.json과 설치된 node_modules의 정확한 버전을 검증할 수 없어 조회하지 못했습니다. 확인 불가 상태는 취약점 없음·정상·안전이 아닙니다.',
      };

      const errorFixedMessages = {
        CANCELLED: '패키지 취약점 조회를 취소했거나 새 요청으로 이전 요청을 중단했습니다. 취소된 조회나 늦게 도착한 이전 응답은 현재 확인 결과가 아니며 취약점 없음·정상·안전이 아닙니다.',
        REQUEST_CANCELLED: '패키지 취약점 조회를 취소했거나 새 요청으로 이전 요청을 중단했습니다. 취소된 조회나 늦게 도착한 이전 응답은 현재 확인 결과가 아니며 취약점 없음·정상·안전이 아닙니다.',
        TIMEOUT: '패키지 취약점 조회 응답 시간이 초과되어 중단했습니다. 조회 실패 상태이며 취약점 없음·정상·안전이 아닙니다. 잠시 뒤 직접 다시 조회하세요.',
        REQUEST_TIMEOUT: '패키지 취약점 조회 응답 시간이 초과되어 중단했습니다. 조회 실패 상태이며 취약점 없음·정상·안전이 아닙니다. 잠시 뒤 직접 다시 조회하세요.',
        CONTRACT_MISMATCH: '패키지 취약점 조회 응답 형식을 검증할 수 없습니다(확인 불가). 취약점 없음·정상·안전으로 간주하지 마세요.',
        SERVICE_UNAVAILABLE: '패키지 취약점 조회 서비스를 지금 사용할 수 없습니다(조회 실패). 잠시 뒤 직접 다시 조회하세요.',
        HOST_REJECTED: '허용되지 않은 접속 주소라 패키지 취약점 조회를 수행하지 않았습니다.',
        ORIGIN_REJECTED: '허용되지 않은 출처에서 온 요청이라 패키지 취약점 조회를 수행하지 않았습니다.',
        REQUEST_INVALID: '패키지 취약점 조회 요청 형식이 올바르지 않아 처리할 수 없습니다.',
      };

      addText(root, 'h3', '설치 패키지 버전 및 알려진 취약점(OSV) 조회 결과');
      addText(
        root,
        'p',
        '학생 코드는 /api/vulnerabilities나 외부 OSV API를 직접 호출하지 않으며, 비공개·사내 패키지 이름을 외부로 전송하지 않습니다. 제공 화면의 「설치 패키지 조회」 및 「취소」 버튼을 사용하세요.',
      );

      if (mode !== undefined && mode !== null) {
        const modeText = Object.hasOwn(modeLabels, mode) ? modeLabels[mode] : modeLabels.unknown;
        addText(root, 'p', `연결 상태: ${modeText}`);
      }

      const normalizedTopStatus = ['idle', 'loading', 'error', 'ok'].includes(status) ? status : 'error';
      root.setAttribute('data-student-vulnerabilities-status', normalizedTopStatus);

      // 1) idle / loading / error 시 이전 표를 남기지 않고 현재 상태만 구분 표시
      if (normalizedTopStatus === 'idle') {
        addText(
          root,
          'p',
          '조회 상태: 조회 전(idle) — 아직 설치 패키지 취약점 조회를 실행하지 않았습니다. 미조회 상태는 취약점 없음(안전)을 뜻하지 않습니다. 위쪽 「설치 패키지 조회」 버튼을 눌러 확인하세요.',
        );
        return root;
      }

      if (normalizedTopStatus === 'loading') {
        addText(
          root,
          'p',
          '조회 상태: 조회 중(loading) — 설치된 패키지의 정확한 버전을 기준으로 취약점 정보를 조회하고 있습니다. 이전 조회 표는 지웠으며 아직 결과가 확정되지 않았습니다.',
        );
        return root;
      }

      if (normalizedTopStatus === 'error') {
        const safeCode = typeof error?.code === 'string' && error.code.trim().length > 0
          ? sanitizeText(error.code, 'UNKNOWN_ERROR')
          : 'UNKNOWN_ERROR';
        const safeRawMessage = typeof error?.message === 'string' && error.message.trim().length > 0
          ? sanitizeText(error.message, '')
          : '';
        const guideMessage = Object.hasOwn(errorFixedMessages, safeCode)
          ? errorFixedMessages[safeCode]
          : '패키지 취약점 조회 요청이 실패하여 결과를 확인할 수 없습니다. 조회 실패는 취약점 없음·정상·안전이 아닙니다.';

        addText(
          root,
          'p',
          `조회 상태: 조회 실패(error) · 오류 코드(code): ${safeCode}${safeRawMessage ? ` — ${safeRawMessage}` : ''}`,
        );
        addText(root, 'p', guideMessage);
        addText(
          root,
          'p',
          '이전 조회 표를 현재 결과처럼 남기지 않았습니다. 자동으로 재시도하지 않으므로 필요하면 제공 화면의 「설치 패키지 조회」 버튼을 직접 다시 누르세요.',
        );
        return root;
      }

      // 2) status === 'ok' 처리 및 data.status 검증
      if (!data || typeof data !== 'object' || Array.isArray(data)) {
        root.setAttribute('data-student-vulnerabilities-status', 'error');
        addText(
          root,
          'p',
          '조회 상태: 조회 실패(error) · 응답 데이터(data) 형식을 확인할 수 없습니다. 취약점 없음(안전)으로 간주하지 마세요.',
        );
        return root;
      }

      const rawScanStatus = typeof data.status === 'string' ? data.status.trim() : '';
      if (!Object.hasOwn(scanStatusLabels, rawScanStatus)) {
        root.setAttribute('data-student-vulnerabilities-status', 'error');
        addText(
          root,
          'p',
          `조회 상태: 조회 확인 불가(unverifiable) · 알 수 없는 전체 조회 상태(${sanitizeText(rawScanStatus, 'unknown')})입니다. 취약점 없음(안전)으로 간주하지 마세요.`,
        );
        return root;
      }

      root.setAttribute('data-student-scan-status', rawScanStatus);
      addText(root, 'p', `전체 조회 결과 상태(data.status): ${scanStatusLabels[rawScanStatus]}`);
      addText(root, 'p', scanStatusNotes[rawScanStatus]);

      // 전달된 경우에만 메타데이터(code, lockfileVersion, lockfileHash, checkedAt, excluded) 표시
      const metaList = document.createElement('ul');
      addText(
        metaList,
        'li',
        '대조 기준: package-lock.json 및 실제 설치된 node_modules 메타데이터의 정확한 설치 버전(^1.2.0 같은 범위 표기 미사용)',
      );
      if (typeof data.code === 'string' && data.code.trim().length > 0) {
        addText(metaList, 'li', `상태 코드(data.code): ${sanitizeText(data.code)}`);
      }
      if (typeof data.message === 'string' && data.message.trim().length > 0) {
        addText(metaList, 'li', `상태 안내(data.message): ${sanitizeText(data.message)}`);
      }
      if (data.lockfileVersion !== undefined && data.lockfileVersion !== null) {
        addText(metaList, 'li', `잠금 파일 버전(lockfileVersion): ${sanitizeText(String(data.lockfileVersion))}`);
      }
      if (typeof data.lockfileHash === 'string' && data.lockfileHash.trim().length > 0) {
        addText(metaList, 'li', `잠금 파일 해시(lockfileHash): ${sanitizeText(data.lockfileHash)}`);
      }
      if (typeof data.checkedAt === 'string' && data.checkedAt.trim().length > 0) {
        addText(metaList, 'li', `전체 조회 시각(checkedAt): ${sanitizeText(data.checkedAt)}`);
      }
      if (data.excluded && typeof data.excluded === 'object') {
        const totalExcluded = Number.isSafeInteger(data.excluded.count)
          ? data.excluded.count
          : [data.excluded.unapproved, data.excluded.unsupported, data.excluded.invalid]
            .filter((n) => Number.isSafeInteger(n) && n >= 0)
            .reduce((acc, n) => acc + n, 0);
        const detailParts = [];
        if (Number.isSafeInteger(data.excluded.unapproved)) detailParts.push(`미승인 ${data.excluded.unapproved}건`);
        if (Number.isSafeInteger(data.excluded.unsupported)) detailParts.push(`미지원 ${data.excluded.unsupported}건`);
        if (Number.isSafeInteger(data.excluded.invalid)) detailParts.push(`형식 오류 ${data.excluded.invalid}건`);
        addText(
          metaList,
          'li',
          `공개 조회 제외 건수(excluded): ${totalExcluded}건${detailParts.length > 0 ? ` (${detailParts.join(', ')})` : ''} — 승인 목록에 없거나 비공개·사내 패키지는 외부 OSV로 전송하지 않고 제외합니다.`,
        );
      }
      root.append(metaList);

      // not_configured / not_checked / unverifiable 상태일 때 안내
      if (rawScanStatus === 'not_configured' || rawScanStatus === 'not_checked' || rawScanStatus === 'unverifiable') {
        addText(
          root,
          'p',
          `현재 전체 상태가 ${scanStatusLabels[rawScanStatus]}이므로 취약점 검증이 완료되지 않았습니다. 이를 "알려진 취약점 없음(안전)"으로 해석하지 마세요.`,
        );
      }

      const packages = Array.isArray(data.packages) ? data.packages : [];
      if (packages.length === 0) {
        if (rawScanStatus === 'complete') {
          addText(root, 'p', '조회 대상 패키지가 없습니다 (빈 목록).');
        } else {
          addText(root, 'p', `표시할 패키지별 조회 행이 없습니다 (전체 상태: ${scanStatusLabels[rawScanStatus]} · 취약점 없음 아님).`);
        }
        return root;
      }

      // 3~5) 패키지 목록 표 렌더링
      const table = document.createElement('table');
      const thead = document.createElement('thead');
      const headRow = document.createElement('tr');
      for (const colTitle of [
        '패키지 이름(name)',
        '설치된 정확한 버전(version)',
        '패키지 조회 상태(status)',
        '취약점 ID 및 수정 시각(vulnerabilities)',
        '조회 출처(source)',
        '패키지 확인 시각(checkedAt)',
      ]) {
        addText(headRow, 'th', colTitle);
      }
      thead.append(headRow);
      table.append(thead);

      const tbody = document.createElement('tbody');
      for (const pkg of packages) {
        const row = document.createElement('tr');
        const pkgName = sanitizeText(pkg?.name, '이름 확인 불가');
        const rawVersion = typeof pkg?.version === 'string' ? pkg.version.trim() : '';
        const hasExactVersion = isExactSemver(rawVersion);
        const versionAttr = hasExactVersion ? rawVersion : 'invalid';
        const versionDisplay = hasExactVersion
          ? `${rawVersion} (설치된 정확한 버전)`
          : `${sanitizeText(rawVersion, '버전 확인 불가')} (정확한 설치 버전 형식이 아님 · 범위 표기 불가 · 확인 불가)`;

        row.setAttribute('data-student-package-name', pkgName);
        row.setAttribute('data-student-package-version', versionAttr);

        const rawPkgStatus = typeof pkg?.status === 'string' ? pkg.status.trim() : 'unverifiable';
        const vulns = Array.isArray(pkg?.vulnerabilities)
          ? pkg.vulnerabilities.filter((v) => v && typeof v === 'object' && typeof v.id === 'string' && v.id.trim().length > 0)
          : [];

        let pkgStatusLabel = '';
        if (!hasExactVersion) {
          pkgStatusLabel = '조회 확인 불가(unverifiable) — 정확한 설치 버전이 아니므로 취약점 없음(안전)으로 인정하지 않음';
        } else if (rawPkgStatus === 'known_vulnerabilities') {
          pkgStatusLabel = '알려진 항목 있음(known_vulnerabilities) — 알려진 취약점이 발견됨';
        } else if (rawPkgStatus === 'none_found') {
          if (vulns.length > 0) {
            pkgStatusLabel = '조회 확인 불가(unverifiable) — 상태와 취약점 목록이 불일치함';
          } else {
            pkgStatusLabel = '알려진 항목 없음(none_found) — 조회 시점 기준 OSV에서 알려진 취약점이 발견되지 않음';
          }
        } else if (rawPkgStatus === 'unverifiable') {
          if (vulns.length > 0) {
            pkgStatusLabel = '일부 확인·전체 조회 확인 불가(unverifiable) — 이미 확인된 취약점은 유지하며 전체 조회는 완료되지 않음(안전 아님)';
          } else {
            pkgStatusLabel = '조회 확인 불가(unverifiable) — 조회하지 못했거나 검증할 수 없음(취약점 없음·정상·안전 아님)';
          }
        } else {
          pkgStatusLabel = `조회 확인 불가(${sanitizeText(rawPkgStatus, 'unverifiable')}) — 취약점 없음·정상·안전 아님`;
        }

        addText(row, 'td', pkgName);
        addText(row, 'td', versionDisplay);
        addText(row, 'td', pkgStatusLabel);

        const vulnCell = document.createElement('td');
        if (vulns.length > 0) {
          const vList = document.createElement('ul');
          for (const v of vulns) {
            const vId = sanitizeText(v.id, 'ID 확인 불가');
            const vMod = sanitizeText(v.modified, '수정 시각 확인 불가');
            addText(vList, 'li', `ID: ${vId} · 수정 시각(modified): ${vMod}`);
          }
          vulnCell.append(vList);
        } else if (hasExactVersion && rawPkgStatus === 'none_found') {
          vulnCell.textContent = '알려진 취약점 ID 없음 (none_found)';
        } else {
          vulnCell.textContent = '전체 조회 확인 불가 (unverifiable · 취약점 없음 아님)';
        }
        row.append(vulnCell);

        addText(row, 'td', sanitizeText(pkg?.source, '출처 확인 불가'));
        addText(row, 'td', sanitizeText(pkg?.checkedAt, '시각 확인 불가'));

        tbody.append(row);
      }

      table.append(tbody);
      root.append(table);

      return root;
    },
  };
}

// ============================================================================
// 복수를결심한인공능지 — 관제 대시보드(상단 카드 4개 + 아래 추이와 기록) & 핵심 기능 3가지 통합 모듈
// - 제공 공통 화면 파일(public/app.js, public/style.css, src/server.mjs)의 계약을 깨지 않고 동작합니다.
// - 모든 외부·서버 문자열은 document.createElement 와 textContent 로만 렌더링합니다 (innerHTML 미사용).
// - 키보드(Tab, Enter, Space)만으로 '내 PC 상태·보안 구성 다시 조회' 등 모든 기능을 조작할 수 있습니다.
// ============================================================================

const DEFAULT_APPEARANCE = Object.freeze({
  appName: '복수를결심한인공능지',
  layoutType: 'control-dashboard-4cards-and-trends',
  coreFeaturesOrder: [
    '핵심 기능 1 · 관제 대시보드 상단 상태 카드 4종 (SDP 연결 상태와 로컬 PC 조회 결과 분리)',
    '핵심 기능 2 · 내 PC 자원(CPU·메모리·디스크) 직전 측정 대비 추이 비교(Δ) 및 임계치 해석',
    '핵심 기능 3 · 내 PC 네트워크 구성 · 방화벽 설정(읽기 전용) · Windows 기록(System·Application 경고·오류 건수)'
  ]
});

export function createStudentView(options = {}) {
  const { api, onChange } = options;
  const baseView = createBaseStudentView(options);

  // 로컬 측정 이력(추이 비교용, 최대 10건 보관) 및 수동 재조회 대기 상태
  const pcHistory = [];
  let manualQueryState = {
    status: 'idle', // 'idle' | 'loading' | 'ok' | 'error'
    lastCheckedAt: null,
    errorCode: null,
    errorMessage: null,
    nextStepGuide: null,
  };
  let lastDiagnosticsData = null;
  let lastSnapshot = {
    me: null,
    devices: null,
    sessions: null,
    notifications: [],
    diagnostics: null,
    events: null,
    mode: 'unknown',
  };

  const formatKstAndIso = (isoStr) => {
    if (typeof isoStr !== 'string' || !isoStr.trim()) return '시각 확인 불가';
    const d = new Date(isoStr);
    if (Number.isNaN(d.getTime())) return isoStr;
    return `${d.toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' })} (${isoStr})`;
  };

  const makeBadge = (kind, customText) => {
    const span = document.createElement('span');
    span.setAttribute('data-student-badge-kind', kind);
    span.style.display = 'inline-block';
    span.style.padding = '2px 8px';
    span.style.marginRight = '6px';
    span.style.borderRadius = '999px';
    span.style.fontSize = '0.75rem';
    span.style.fontWeight = '700';
    if (kind === 'measured') {
      span.style.background = '#e5f4ea';
      span.style.color = '#1d7a3e';
      span.style.border = '1px solid #1d7a3e';
      span.textContent = customText || '[실측값 · 내 PC]';
    } else if (kind === 'example') {
      span.style.background = '#fff4e0';
      span.style.color = '#9a5b00';
      span.style.border = '1px solid #9a5b00';
      span.textContent = customText || '[예시값 · 설명용(실제 조회 아님)]';
    } else if (kind === 'sdp-disconnected') {
      span.style.background = '#fdeceb';
      span.style.color = '#b42318';
      span.style.border = '1px solid #b42318';
      span.textContent = customText || '[SDP 미연결 · 로컬 PC 조회와 별개]';
    } else {
      span.style.background = '#eceff3';
      span.style.color = '#4b5563';
      span.style.border = '1px solid #4b5563';
      span.textContent = customText || '[확인 불가]';
    }
    return span;
  };

  const recordPcHistoryIfNew = (diagData) => {
    if (!diagData || typeof diagData !== 'object' || !diagData.pcTelemetry) return;
    const t = diagData.pcTelemetry;
    const stamp = t.measuredAt || diagData.checkedAt;
    if (!stamp) return;
    if (pcHistory.length > 0 && pcHistory[pcHistory.length - 1].measuredAt === stamp) return;
    pcHistory.push({
      measuredAt: stamp,
      cpuPercent: typeof t.cpu?.usagePercent === 'number' ? t.cpu.usagePercent : null,
      memUsedGiB: typeof t.memory?.usedGiB === 'number' ? t.memory.usedGiB : null,
      memPercent: typeof t.memory?.usagePercent === 'number' ? t.memory.usagePercent : null,
      diskFreeGiB: typeof t.disk?.freeGiB === 'number' ? t.disk.freeGiB : null,
      diskFreePercent: typeof t.disk?.freePercent === 'number' ? t.disk.freePercent : null,
    });
    if (pcHistory.length > 10) pcHistory.shift();
  };

  // 사용자가 '내 PC 상태·보안 구성 다시 조회' 버튼을 눌렀을 때 실행 (자동 재시도 없음)
  const triggerManualRefresh = () => {
    if (manualQueryState.status === 'loading') return;
    manualQueryState = {
      status: 'loading',
      lastCheckedAt: manualQueryState.lastCheckedAt,
      errorCode: null,
      errorMessage: null,
      nextStepGuide: null,
    };
    if (typeof onChange === 'function') onChange();

    try {
      const diagBtn = typeof document !== 'undefined' ? document.getElementById('diag-load') : null;
      if (diagBtn && !diagBtn.disabled) {
        diagBtn.click();
        setTimeout(() => {
          if (manualQueryState.status === 'loading') {
            manualQueryState.status = lastDiagnosticsData ? 'ok' : 'error';
            if (!lastDiagnosticsData) {
              manualQueryState.errorCode = 'DIAGNOSTICS_NOT_LOADED';
              manualQueryState.errorMessage = '도움정보(진단 API) 응답을 아직 받지 못했습니다.';
              manualQueryState.nextStepGuide = '위쪽 제공 화면의 「도움정보 불러오기」 또는 「다시 불러오기」 버튼을 직접 눌러 서버 응답을 확인하세요.';
            }
            if (typeof onChange === 'function') onChange();
          }
        }, 1200);
        return;
      }
      if (api && typeof api.get === 'function') {
        api.get('/api/me').then((res) => {
          if (res && res.ok) {
            manualQueryState = {
              status: 'ok',
              lastCheckedAt: res.meta?.checkedAt || new Date().toISOString(),
              errorCode: null,
              errorMessage: null,
              nextStepGuide: null,
            };
          } else {
            manualQueryState = {
              status: 'error',
              lastCheckedAt: new Date().toISOString(),
              errorCode: res?.error?.code || 'ENGINE_NOT_CONNECTED',
              errorMessage: res?.error?.message || '원천 서버 연결을 확인할 수 없습니다.',
              nextStepGuide: 'SDP 서버 미연결 상태입니다. 내 PC 상태 실측을 갱신하려면 위쪽 「도움정보 불러오기」 버튼을 직접 누르세요.',
            };
          }
          if (typeof onChange === 'function') onChange();
        }).catch(() => {
          manualQueryState = {
            status: 'error',
            lastCheckedAt: new Date().toISOString(),
            errorCode: 'NETWORK_ERROR',
            errorMessage: '로컬 서버 응답을 읽지 못했습니다.',
            nextStepGuide: '앱 실행 창(PowerShell)이 켜져 있는지 확인한 뒤 「내 PC 상태·보안 구성 다시 조회」 버튼을 직접 다시 누르세요.',
          };
          if (typeof onChange === 'function') onChange();
        });
      }
    } catch {
      manualQueryState = {
        status: 'error',
        lastCheckedAt: new Date().toISOString(),
        errorCode: 'MANUAL_QUERY_FAILED',
        errorMessage: '수동 재조회 요청 중 오류가 발생했습니다.',
        nextStepGuide: '화면을 새로고침하거나 위쪽 「도움정보 불러오기」 버튼을 직접 누르세요.',
      };
      if (typeof onChange === 'function') onChange();
    }
  };

  // 핵심 기능 3가지가 맨 위에 보이게 구성한 통합 관제 대시보드 패널
  const buildCoreDashboardPanel = (snap) => {
    const wrapper = document.createElement('section');
    wrapper.setAttribute('data-student-dashboard', 'revenge-ai-control-dashboard');
    wrapper.style.marginBottom = '18px';
    wrapper.style.padding = '16px';
    wrapper.style.background = '#f8fafc';
    wrapper.style.border = '2px solid #2357c6';
    wrapper.style.borderRadius = '8px';

    // 상단 헤더 + 수동 '다시 조회' 버튼 + 대기 표시
    const topRow = document.createElement('div');
    topRow.style.display = 'flex';
    topRow.style.justifyContent = 'space-between';
    topRow.style.alignItems = 'center';
    topRow.style.flexWrap = 'wrap';
    topRow.style.gap = '10px';
    topRow.style.marginBottom = '12px';

    const titleBox = document.createElement('div');
    const mainTitle = document.createElement('h3');
    mainTitle.style.margin = '0 0 4px 0';
    mainTitle.textContent = `${DEFAULT_APPEARANCE.appName} · 관제 대시보드 (핵심 기능 3가지 우선 배치)`;
    const subNote = document.createElement('p');
    subNote.style.margin = '0';
    subNote.style.fontSize = '0.85rem';
    subNote.style.color = '#4b5563';
    subNote.textContent = '제공 공통 기능(GET /api/diagnostics의 checkedAt·engine.mode)을 재사용하며, 내 PC 실측값과 설명용 예시값·SDP 미연결 상태를 엄격히 분리합니다.';
    titleBox.append(mainTitle, subNote);

    const actionBox = document.createElement('div');
    actionBox.style.display = 'flex';
    actionBox.style.alignItems = 'center';
    actionBox.style.gap = '8px';
    actionBox.style.flexWrap = 'wrap';

    const refreshBtn = document.createElement('button');
    refreshBtn.type = 'button';
    refreshBtn.className = 'btn';
    refreshBtn.setAttribute('data-student-action', 'refresh-pc-status');
    refreshBtn.setAttribute('aria-label', '내 PC 상태·보안 구성 다시 조회');
    refreshBtn.textContent = manualQueryState.status === 'loading'
      ? '조회 대기 중… (다시 조회 진행 중)'
      : '내 PC 상태·보안 구성 다시 조회';
    refreshBtn.disabled = manualQueryState.status === 'loading';
    refreshBtn.addEventListener('click', triggerManualRefresh);

    const waitBadge = document.createElement('span');
    waitBadge.setAttribute('role', 'status');
    waitBadge.setAttribute('aria-live', 'polite');
    waitBadge.setAttribute('data-student-query-status', manualQueryState.status);
    waitBadge.style.fontSize = '0.82rem';
    waitBadge.style.fontWeight = '600';
    if (manualQueryState.status === 'loading') {
      waitBadge.style.color = '#9a5b00';
      waitBadge.textContent = '⏳ 대기 표시: 로컬 PC 상태 및 진단 정보를 조회하는 중입니다…';
    } else if (manualQueryState.status === 'error') {
      waitBadge.style.color = '#b42318';
      waitBadge.textContent = `조회 실패(${manualQueryState.errorCode || 'ERROR'}): ${manualQueryState.errorMessage || ''} → 다음 할 일: ${manualQueryState.nextStepGuide || '위쪽 도움정보 불러오기를 직접 누르세요.'}`;
    } else if (lastDiagnosticsData) {
      waitBadge.style.color = '#1d7a3e';
      waitBadge.textContent = `최근 로컬 실측 완료: ${formatKstAndIso(lastDiagnosticsData.checkedAt)}`;
    } else {
      waitBadge.style.color = '#4b5563';
      waitBadge.textContent = '대기 상태(idle): 「내 PC 상태·보안 구성 다시 조회」 또는 위쪽 「도움정보 불러오기」를 누르면 실측값이 갱신됩니다.';
    }

    actionBox.append(refreshBtn, waitBadge);
    topRow.append(titleBox, actionBox);
    wrapper.append(topRow);

    const isDemo = snap.mode === 'demo' || snap.me?.mode === 'demo' || snap.devices?.mode === 'demo';
    const isSdpConnected = snap.mode === 'connected' || snap.me?.mode === 'connected';
    const diagOk = snap.diagnostics?.status === 'ok' && snap.diagnostics?.data && typeof snap.diagnostics.data === 'object';
    const diagData = diagOk ? snap.diagnostics.data : null;
    if (diagData) {
      lastDiagnosticsData = diagData;
      recordPcHistoryIfNew(diagData);
      if (manualQueryState.status === 'loading') {
        manualQueryState.status = 'ok';
      }
    }
    const tele = diagData?.pcTelemetry || null;

    // =========================================================================
    // [핵심 기능 1] 관제 대시보드 상단 상태 카드 4개 (맨 위 배치)
    // =========================================================================
    const sec1 = document.createElement('section');
    sec1.setAttribute('data-student-core-feature', '1-top-4-status-cards');
    sec1.style.marginBottom = '14px';

    const sec1Title = document.createElement('h4');
    sec1Title.style.margin = '0 0 8px 0';
    sec1Title.style.color = '#1c2430';
    sec1Title.textContent = '핵심 기능 1 · 관제 대시보드 상단 상태 카드 4종 (SDP 연결 상태와 내 PC 로컬 조회 분리)';
    sec1.append(sec1Title);

    const cardGrid = document.createElement('div');
    cardGrid.style.display = 'grid';
    cardGrid.style.gridTemplateColumns = 'repeat(4, minmax(0, 1fr))';
    cardGrid.style.gap = '10px';

    const makeCard = (cardId, titleText) => {
      const article = document.createElement('article');
      article.setAttribute('data-student-status-card', cardId);
      article.style.background = '#ffffff';
      article.style.border = '1px solid #cbd5e1';
      article.style.borderRadius = '6px';
      article.style.padding = '10px 12px';
      const h = document.createElement('h4');
      h.style.margin = '0 0 6px 0';
      h.style.fontSize = '0.9rem';
      h.textContent = titleText;
      article.append(h);
      return article;
    };

    // 카드 1: SDP 서버 연결 상태 (로컬 PC 조회 성공과 섞지 않고 분리)
    const c1 = makeCard('card-1-sdp-connection', '① SDP 서버 연결 상태');
    const c1P = document.createElement('p');
    c1P.style.margin = '0';
    c1P.style.fontSize = '0.84rem';
    if (isSdpConnected) {
      c1P.append(makeBadge('measured', '[실측값 · SDP 연결됨]'));
      const s = document.createElement('span');
      s.textContent = `SDP 연결됨(connected) · 사용자: ${snap.me?.data?.user?.label || '확인됨'}`;
      c1P.append(s);
    } else if (isDemo) {
      c1P.append(makeBadge('example', '[예시값 · demo 모드]'));
      const s = document.createElement('span');
      s.textContent = 'SDP 미연결 (현재 화면은 예제 자료 demo 모드이며 실제 SDP 서버 연결이 아닙니다)';
      c1P.append(s);
    } else {
      c1P.append(makeBadge('sdp-disconnected', '[SDP 미연결 · ENGINE_NOT_CONNECTED]'));
      const s = document.createElement('span');
      s.textContent = 'SDP 서버에 실제로 연결되지 않았습니다(disconnected). 내 PC 로컬 상태 조회 성공을 SDP 연결 성공으로 간주하지 않습니다.';
      c1P.append(s);
    }
    c1.append(c1P);

    // 카드 2: 등록 기기 · 현재 세션 상태
    const c2 = makeCard('card-2-device-session', '② 기기 · 세션 보안 상태');
    const c2P = document.createElement('p');
    c2P.style.margin = '0';
    c2P.style.fontSize = '0.84rem';
    if (snap.devices?.status === 'ok' && Array.isArray(snap.devices.data)) {
      c2P.append(makeBadge(isDemo ? 'example' : 'measured', isDemo ? '[예시값 · demo]' : '[실측값 · SDP]'));
      const s = document.createElement('span');
      const sessCnt = Array.isArray(snap.sessions?.data) ? snap.sessions.data.length : 0;
      s.textContent = `등록 기기: ${snap.devices.data.length}대 · 현재 세션: ${sessCnt}건`;
      c2P.append(s);
    } else {
      c2P.append(makeBadge('unverifiable', '[확인 불가 · SDP 미연결]'));
      const s = document.createElement('span');
      s.textContent = '확인 불가 — 사유: SDP 호스트가 연결되지 않아 원천 기기·세션 목록을 읽지 못했습니다(예시 값을 정상처럼 표시하지 않음).';
      c2P.append(s);
    }
    c2.append(c2P);

    // 카드 3: 내 PC 자원 실측 요약 (CPU · 메모리 · 디스크)
    const c3 = makeCard('card-3-pc-resources', '③ 내 PC 자원 요약 (일반 권한)');
    const c3P = document.createElement('p');
    c3P.style.margin = '0';
    c3P.style.fontSize = '0.84rem';
    if (tele && tele.cpu?.status === 'ok' && tele.memory?.status === 'ok') {
      c3P.append(makeBadge('measured', '[실측값 · 내 PC]'));
      const diskStr = tele.disk?.status === 'ok' ? `${tele.disk.freeGiB} GiB 남음` : '디스크 확인 불가';
      const s = document.createElement('span');
      s.textContent = `CPU ${tele.cpu.usagePercent} % · 메모리 ${tele.memory.usedGiB} GiB (${tele.memory.usagePercent} %) · 디스크 ${diskStr} · 시각: ${formatKstAndIso(tele.measuredAt)}`;
      c3P.append(s);
    } else {
      c3P.append(makeBadge('unverifiable', '[확인 불가 · 측정 전]'));
      const s = document.createElement('span');
      s.textContent = '확인 불가 — 사유: 아직 「내 PC 상태·보안 구성 다시 조회」(또는 도움정보 불러오기)를 실행하지 않았습니다.';
      c3P.append(s);
    }
    c3.append(c3P);

    // 카드 4: 내 PC 보안·이벤트 요약 (네트워크 · 방화벽 · Windows 기록)
    const c4 = makeCard('card-4-pc-security', '④ 내 PC 방화벽 · Windows 기록');
    const c4P = document.createElement('p');
    c4P.style.margin = '0';
    c4P.style.fontSize = '0.84rem';
    if (tele) {
      c4P.append(makeBadge('measured', '[실측값 · 내 PC 읽기 전용]'));
      const netCnt = tele.network?.status === 'ok' ? `${tele.network.interfaces.length}개 인터페이스` : '네트워크 확인 불가';
      const fwStr = tele.firewall?.status === 'ok' ? tele.firewall.summary : '방화벽 확인 불가';
      const evStr = tele.windowsEvents?.status === 'ok'
        ? `경고·오류 합계 ${tele.windowsEvents.totalCount}건`
        : 'Windows 기록 확인 불가';
      const s = document.createElement('span');
      s.textContent = `${netCnt} · 방화벽: ${fwStr} · 최근 24h 기록: ${evStr} (침해·공격 탐지 결과 아님)`;
      c4P.append(s);
    } else {
      c4P.append(makeBadge('unverifiable', '[확인 불가 · 측정 전]'));
      const s = document.createElement('span');
      s.textContent = '확인 불가 — 사유: 아직 로컬 PC 진단을 실행하지 않았습니다. 위 「다시 조회」 버튼을 눌러 확인하세요.';
      c4P.append(s);
    }
    c4.append(c4P);

    cardGrid.append(c1, c2, c3, c4);
    sec1.append(cardGrid);
    wrapper.append(sec1);

    // =========================================================================
    // [핵심 기능 2] 내 PC 자원(CPU·메모리·디스크) 실측 + 직전 측정 대비 추이 비교(Δ) 및 해석기
    // =========================================================================
    const sec2 = document.createElement('section');
    sec2.setAttribute('data-student-core-feature', '2-pc-resource-trend');
    sec2.style.marginBottom = '14px';
    sec2.style.padding = '12px';
    sec2.style.background = '#ffffff';
    sec2.style.border = '1px solid #cbd5e1';
    sec2.style.borderRadius = '6px';

    const sec2Title = document.createElement('h4');
    sec2Title.style.margin = '0 0 6px 0';
    sec2Title.textContent = '핵심 기능 2 · 내 PC 상태(CPU·메모리·디스크) 실측 및 직전 측정 대비 추이 비교(Δ) · 상태 설명';
    sec2.append(sec2Title);

    const basisNote = document.createElement('p');
    basisNote.style.margin = '0 0 8px 0';
    basisNote.style.fontSize = '0.82rem';
    basisNote.style.color = '#4b5563';
    basisNote.textContent = '제공 근거 재사용: GET /api/diagnostics 의 checkedAt 시각 및 requestId 응답 통로를 그대로 사용하며, 관리자 권한 없이 일반 사용자 권한(node:os, fs.statfs)으로만 읽습니다.';
    sec2.append(basisNote);

    if (!tele) {
      const emptyP = document.createElement('p');
      emptyP.style.margin = '0 0 6px 0';
      emptyP.append(makeBadge('unverifiable', '[확인 불가 · 아직 측정 전]'));
      const s = document.createElement('span');
      s.textContent = 'CPU 사용률(%), 메모리 사용량(GiB/%), 디스크 남은 공간(GiB/%): 확인 불가 — 이유: 아직 「내 PC 상태·보안 구성 다시 조회」 또는 「도움정보 불러오기」를 누르지 않았습니다. (읽지 못한 값에 예시 숫자를 정상처럼 채우지 않습니다.)';
      emptyP.append(s);
      sec2.append(emptyP);

      const exP = document.createElement('p');
      exP.style.margin = '0';
      exP.style.fontSize = '0.82rem';
      exP.append(makeBadge('example', '[예시값 · 설명용(실제 조회 결과 아님)]'));
      const exS = document.createElement('span');
      exS.textContent = '설명용 판정 기준 예시: CPU·메모리 사용률 80 % 미만 및 디스크 여유 공간 15 % 이상이면 「자원 여유(정상)」, 그 이상이면 「주의/혼잡」으로 해석하며 2회 이상 조회 시 직전 측정 대비 증감(±%p, ±GiB)을 표시합니다.';
      exP.append(exS);
      sec2.append(exP);
    } else {
      const mTime = formatKstAndIso(tele.measuredAt || diagData.checkedAt);
      const resList = document.createElement('ul');
      resList.style.margin = '0 0 8px 0';
      resList.style.paddingLeft = '20px';

      // 1) CPU 사용률
      const liCpu = document.createElement('li');
      if (tele.cpu?.status === 'ok') {
        liCpu.append(makeBadge('measured', '[실측값 · 내 PC]'));
        const s = document.createElement('span');
        s.textContent = `CPU 사용률: ${tele.cpu.usagePercent} % (논리 코어 ${tele.cpu.cores}개 · 모델: ${tele.cpu.model || '확인됨'}) · 측정 방식: ${tele.cpu.method} · 잰 시각: ${mTime}`;
        liCpu.append(s);
      } else {
        liCpu.append(makeBadge('unverifiable', '[확인 불가]'));
        const s = document.createElement('span');
        s.textContent = `CPU 사용률: 확인 불가 — 이유: ${tele.cpu?.reason || '일반 권한 OS CPU 틱 정보를 읽지 못했습니다.'} · 확인 시각: ${mTime}`;
        liCpu.append(s);
      }
      resList.append(liCpu);

      // 2) 메모리 사용량
      const liMem = document.createElement('li');
      if (tele.memory?.status === 'ok') {
        liMem.append(makeBadge('measured', '[실측값 · 내 PC]'));
        const s = document.createElement('span');
        s.textContent = `메모리 사용량: ${tele.memory.usedGiB} GiB / 전체 ${tele.memory.totalGiB} GiB (사용률 ${tele.memory.usagePercent} % · 여유 ${tele.memory.freeGiB} GiB) · 잰 시각: ${mTime}`;
        liMem.append(s);
      } else {
        liMem.append(makeBadge('unverifiable', '[확인 불가]'));
        const s = document.createElement('span');
        s.textContent = `메모리 사용량: 확인 불가 — 이유: ${tele.memory?.reason || '일반 권한 메모리 정보를 읽지 못했습니다.'} · 확인 시각: ${mTime}`;
        liMem.append(s);
      }
      resList.append(liMem);

      // 3) 디스크 남은 공간
      const liDisk = document.createElement('li');
      if (tele.disk?.status === 'ok') {
        liDisk.append(makeBadge('measured', '[실측값 · 내 PC]'));
        const s = document.createElement('span');
        s.textContent = `디스크 남은 공간 (${tele.disk.mount || '현재 작업 드라이브'}): ${tele.disk.freeGiB} GiB 남음 / 전체 ${tele.disk.totalGiB} GiB (남은 비율 ${tele.disk.freePercent} % · 사용률 ${tele.disk.usedPercent} %) · 잰 시각: ${mTime}`;
        liDisk.append(s);
      } else {
        liDisk.append(makeBadge('unverifiable', '[확인 불가]'));
        const s = document.createElement('span');
        s.textContent = `디스크 남은 공간: 확인 불가 — 이유: ${tele.disk?.reason || '일반 권한 statfs 호출로 디스크 블록 정보를 읽지 못했습니다.'} · 확인 시각: ${mTime}`;
        liDisk.append(s);
      }
      resList.append(liDisk);
      sec2.append(resList);

      // 추이 비교(Δ) 및 자동 상태 설명
      const trendP = document.createElement('p');
      trendP.style.margin = '0 0 6px 0';
      trendP.style.fontWeight = '600';
      if (pcHistory.length >= 2) {
        const prev = pcHistory[pcHistory.length - 2];
        const curr = pcHistory[pcHistory.length - 1];
        const fmtDelta = (c, p, unit) => {
          if (typeof c !== 'number' || typeof p !== 'number') return '확인 불가';
          const diff = Number((c - p).toFixed(2));
          const arrow = diff > 0 ? '▲' : diff < 0 ? '▼' : '▬';
          const sign = diff > 0 ? '+' : '';
          return `${sign}${diff} ${unit} ${arrow}`;
        };
        trendP.append(makeBadge('measured', `[실측 추이 비교 · 총 ${pcHistory.length}회 누적]`));
        const s = document.createElement('span');
        s.textContent = `직전 측정(${formatKstAndIso(prev.measuredAt)}) 대비 변화량: CPU ${fmtDelta(curr.cpuPercent, prev.cpuPercent, '%p')} · 메모리 ${fmtDelta(curr.memUsedGiB, prev.memUsedGiB, 'GiB')} (${fmtDelta(curr.memPercent, prev.memPercent, '%p')}) · 디스크 여유 공간 ${fmtDelta(curr.diskFreeGiB, prev.diskFreeGiB, 'GiB')}`;
        trendP.append(s);
      } else {
        trendP.append(makeBadge('measured', '[실측 기준점 1회차 기록됨]'));
        const s = document.createElement('span');
        s.textContent = '첫 번째 실측 기준점이 저장되었습니다. 「내 PC 상태·보안 구성 다시 조회」 버튼을 한 번 더 누르면 직전 측정 시각 대비 CPU(%p)·메모리(GiB)·디스크(GiB) 증감 추이가 바로 비교됩니다.';
        trendP.append(s);
      }
      sec2.append(trendP);

      // 상태 해석 설명
      const explainP = document.createElement('p');
      explainP.style.margin = '0';
      explainP.style.fontSize = '0.84rem';
      const cpuWarn = typeof tele.cpu?.usagePercent === 'number' && tele.cpu.usagePercent >= 80;
      const memWarn = typeof tele.memory?.usagePercent === 'number' && tele.memory.usagePercent >= 80;
      const diskWarn = typeof tele.disk?.freePercent === 'number' && tele.disk.freePercent < 15;
      explainP.append(makeBadge('measured', '[실측 기반 상태 설명]'));
      const expSpan = document.createElement('span');
      if (cpuWarn || memWarn || diskWarn) {
        expSpan.textContent = '해석: 현재 일부 자원 사용률이 주의 임계치(CPU·메모리 80% 이상 또는 디스크 여유 15% 미만)에 도달했습니다. 불필요한 백그라운드 프로세스나 디스크 용량을 점검하세요.';
      } else {
        expSpan.textContent = '해석: 현재 CPU·메모리·디스크 여유 공간이 모두 권장 기준 범위 안에 있어 로컬 보안 Agent 구동에 여유가 있습니다(정상).';
      }
      explainP.append(expSpan);
      sec2.append(explainP);
    }
    wrapper.append(sec2);

    // =========================================================================
    // [핵심 기능 3] 내 PC 네트워크 구성 · 방화벽 설정(읽기 전용) · Windows 기록 경고·오류 건수
    // =========================================================================
    const sec3 = document.createElement('section');
    sec3.setAttribute('data-student-core-feature', '3-pc-security-posture');
    sec3.style.padding = '12px';
    sec3.style.background = '#ffffff';
    sec3.style.border = '1px solid #cbd5e1';
    sec3.style.borderRadius = '6px';

    const sec3Title = document.createElement('h4');
    sec3Title.style.margin = '0 0 6px 0';
    sec3Title.textContent = '핵심 기능 3 · 이 PC의 네트워크 구성 · 방화벽 설정(읽기 전용) · 최근 Windows 기록(System·Application) 경고·오류 건수';
    sec3.append(sec3Title);

    // 필수 고지 문구: 침해·공격 탐지 결과가 아님 + 방화벽 읽기 전용 + SDP 미연결 분리
    const disclaimerP = document.createElement('p');
    disclaimerP.setAttribute('data-student-security-disclaimer', 'not-intrusion-detection');
    disclaimerP.style.margin = '0 0 8px 0';
    disclaimerP.style.padding = '8px 10px';
    disclaimerP.style.background = '#fff4e0';
    disclaimerP.style.border = '1px solid #9a5b00';
    disclaimerP.style.borderRadius = '6px';
    disclaimerP.style.fontSize = '0.84rem';
    disclaimerP.style.fontWeight = '600';
    disclaimerP.textContent = '⚠️ 중요 안내: 아래 최근 Windows 기록(System·Application)의 경고·오류 건수는 일반 운영체제 이벤트 통계이며, 침해나 공격 탐지 결과가 아닙니다. 또한 방화벽과 보안 설정은 일반 권한으로 읽기만 수행하며 절대 설정을 변경하지 않습니다. SDP 서버 연결 상태(현재: ' + (isSdpConnected ? 'SDP 연결됨' : 'SDP 미연결') + ')는 이 로컬 PC 조회 결과와 별개입니다.';
    sec3.append(disclaimerP);

    if (!tele) {
      const p = document.createElement('p');
      p.style.margin = '0';
      p.append(makeBadge('unverifiable', '[확인 불가 · 아직 측정 전]'));
      const s = document.createElement('span');
      s.textContent = '네트워크 구성 · 방화벽 설정 · Windows 기록(System·Application) 건수: 확인 불가 — 이유: 아직 「내 PC 상태·보안 구성 다시 조회」(또는 도움정보 불러오기)를 실행하지 않았습니다.';
      p.append(s);
      sec3.append(p);
    } else {
      const mTime = formatKstAndIso(tele.measuredAt || diagData.checkedAt);
      const secList = document.createElement('ul');
      secList.style.margin = '0';
      secList.style.paddingLeft = '20px';

      // 1) 네트워크 구성
      const liNet = document.createElement('li');
      if (tele.network?.status === 'ok' && Array.isArray(tele.network.interfaces)) {
        liNet.append(makeBadge('measured', '[실측값 · 내 PC]'));
        const ifaceText = tele.network.interfaces.length > 0
          ? tele.network.interfaces.map(i => `${i.name}(${i.family}: ${i.address} / 넷마스크 ${i.netmask})`).join(', ')
          : '활성 외부 네트워크 인터페이스 0개 (loopback 전용)';
        const s = document.createElement('span');
        s.textContent = `네트워크 구성 (총 ${tele.network.interfaces.length}개 활성 인터페이스): ${ifaceText} · 잰 시각: ${mTime}`;
        liNet.append(s);
      } else {
        liNet.append(makeBadge('unverifiable', '[확인 불가]'));
        const s = document.createElement('span');
        s.textContent = `네트워크 구성: 확인 불가 — 이유: ${tele.network?.reason || '일반 권한으로 네트워크 인터페이스 목록을 읽지 못했습니다.'} · 확인 시각: ${mTime}`;
        liNet.append(s);
      }
      secList.append(liNet);

      // 2) 방화벽 설정 (읽기 전용)
      const liFw = document.createElement('li');
      if (tele.firewall?.status === 'ok' && Array.isArray(tele.firewall.profiles)) {
        liFw.append(makeBadge('measured', '[실측값 · 내 PC 읽기 전용]'));
        const profText = tele.firewall.profiles.map(p => `${p.profile}: ${p.state}`).join(' · ');
        const s = document.createElement('span');
        s.textContent = `방화벽 설정 (읽기 전용 · 변경 없음): ${profText} (${tele.firewall.summary}) · 잰 시각: ${mTime}`;
        liFw.append(s);
      } else {
        liFw.append(makeBadge('unverifiable', '[확인 불가]'));
        const s = document.createElement('span');
        s.textContent = `방화벽 설정 (읽기 전용): 확인 불가 — 이유: ${tele.firewall?.reason || '현재 OS 환경 또는 일반 사용자 권한에서 방화벽 프로필 상태를 읽을 수 없습니다(설정을 바꾸거나 관리자 권한을 요청하지 않음).'} · 확인 시각: ${mTime}`;
        liFw.append(s);
      }
      secList.append(liFw);

      // 3) 최근 Windows 기록 (System · Application 경고·오류 건수)
      const liEv = document.createElement('li');
      if (tele.windowsEvents?.status === 'ok') {
        const we = tele.windowsEvents;
        liEv.append(makeBadge('measured', '[실측값 · 내 PC]'));
        const s = document.createElement('span');
        const sysPart = we.system?.status === 'ok'
          ? `System 로그(최근 ${we.windowHours || 24}시간): 경고 ${we.system.warningCount}건 · 오류 ${we.system.errorCount}건`
          : `System 로그: 확인 불가(사유: ${we.system?.reason || '권한 제한'})`;
        const appPart = we.application?.status === 'ok'
          ? `Application 로그(최근 ${we.windowHours || 24}시간): 경고 ${we.application.warningCount}건 · 오류 ${we.application.errorCount}건`
          : `Application 로그: 확인 불가(사유: ${we.application?.reason || '권한 제한'})`;
        s.textContent = `최근 Windows 기록 경고·오류 건수 — ${sysPart} / ${appPart} (합계 ${we.totalCount}건 · ※ 이 건수는 침해나 공격 탐지 결과가 아닙니다) · 잰 시각: ${mTime}`;
        liEv.append(s);
      } else {
        liEv.append(makeBadge('unverifiable', '[확인 불가]'));
        const s = document.createElement('span');
        s.textContent = `최근 Windows 기록(System·Application 경고·오류 건수): 확인 불가 — 이유: ${tele.windowsEvents?.reason || '일반 사용자 권한 제한 또는 비-Windows 환경으로 인해 이벤트 로그를 읽을 수 없습니다(관리자 권한 상승 시도 안 함 · 이 건수는 침해나 공격 탐지 결과가 아닙니다).'} · 확인 시각: ${mTime}`;
        liEv.append(s);
      }
      secList.append(liEv);
      sec3.append(secList);
    }
    wrapper.append(sec3);

    return wrapper;
  };

  return {
    ...baseView,
    renderIdentity(input = {}) {
      lastSnapshot.me = input.me || lastSnapshot.me;
      lastSnapshot.devices = input.devices || lastSnapshot.devices;
      lastSnapshot.sessions = input.sessions || lastSnapshot.sessions;
      lastSnapshot.mode = input.me?.mode || input.devices?.mode || lastSnapshot.mode;
      const out = baseView.renderIdentity(input);
      if (out && typeof out === 'object' && typeof out.prepend === 'function') {
        const modeBanner = document.createElement('p');
        modeBanner.style.margin = '0 0 8px 0';
        const isDemo = input.me?.mode === 'demo';
        const isConn = input.me?.mode === 'connected';
        modeBanner.append(
          isConn
            ? makeBadge('measured', '[실측값 · SDP 연결됨]')
            : isDemo
              ? makeBadge('example', '[예시값 · demo 설명용]')
              : makeBadge('sdp-disconnected', '[SDP 미연결 · 로컬 PC 조회와 별개]')
        );
        const s = document.createElement('span');
        s.textContent = isConn
          ? 'SDP 서버에서 확인한 본인 계정·기기·세션 정보입니다.'
          : isDemo
            ? '현재 표시된 사용자·기기·세션은 데모(demo) 예제 값이며 실제 조회 결과가 아닙니다.'
            : '현재 SDP 서버에 연결되지 않았습니다(SDP 미연결). 아래 내 PC 상태 실측은 「학생 상태·알림 표시」 칸에서 따로 확인하세요.';
        modeBanner.append(s);
        out.prepend(modeBanner);
      }
      return out;
    },
    renderStatus(input = {}) {
      lastSnapshot.devices = input.devices || lastSnapshot.devices;
      lastSnapshot.sessions = input.sessions || lastSnapshot.sessions;
      lastSnapshot.notifications = input.notifications || lastSnapshot.notifications;
      lastSnapshot.diagnostics = input.diagnostics || lastSnapshot.diagnostics;
      lastSnapshot.mode = input.mode || input.devices?.mode || lastSnapshot.mode;
      const out = baseView.renderStatus(input);
      if (out && typeof out === 'object' && typeof out.prepend === 'function') {
        out.prepend(buildCoreDashboardPanel(lastSnapshot));
      }
      return out;
    },
    renderEvents(input = {}) {
      lastSnapshot.events = input;
      const out = baseView.renderEvents(input);
      if (out && typeof out === 'object' && typeof out.prepend === 'function') {
        const trendBanner = document.createElement('section');
        trendBanner.setAttribute('data-student-events-trend', 'true');
        trendBanner.style.marginBottom = '12px';
        trendBanner.style.padding = '10px 12px';
        trendBanner.style.background = '#f8fafc';
        trendBanner.style.border = '1px solid #cbd5e1';
        trendBanner.style.borderRadius = '6px';
        const p = document.createElement('p');
        p.style.margin = '0';
        p.style.fontSize = '0.85rem';
        const isDemo = input?.mode === 'demo';
        const rows = Array.isArray(input?.data) ? input.data : [];
        if (input?.status === 'ok' && rows.length > 0) {
          p.append(makeBadge(isDemo ? 'example' : 'measured', isDemo ? '[예시값 · demo 기록]' : '[실측값 · SDP 보안 기록]'));
          const xdrCnt = rows.filter(r => r?.kind === 'xdr').length;
          const accCnt = rows.filter(r => r?.kind === 'access').length;
          const s = document.createElement('span');
          s.textContent = `기록 추이 요약: 총 ${rows.length}건 (접속 기록 ${accCnt}건 · 저장된 XDR 경보 ${xdrCnt}건) · 아래 선택 상자와 상세 버튼(키보드 Tab·Enter 지원)으로 근거를 확인하세요.`;
          p.append(s);
        } else {
          p.append(makeBadge('sdp-disconnected', '[SDP 미연결 · 보안 기록 확인 불가]'));
          const s1 = document.createElement('span');
          s1.textContent = 'SDP 서버에 연결되지 않아 원천 접속·XDR 기록을 불러오지 못했습니다(내 PC 로컬 이벤트 로그 건수와 섞지 않음). ';
          p.append(s1);
          p.append(makeBadge('example', '[예시값 · 설명용]'));
          const s2 = document.createElement('span');
          s2.textContent = '예시 형태: 연결 시 최근 40건 범위의 access(접속) 및 xdr(경보) 기록이 시간순으로 표시됩니다.';
          p.append(s2);
        }
        trendBanner.append(p);
        out.prepend(trendBanner);
      }
      return out;
    }
  };
}

'@
[IO.File]::WriteAllText($ExtTarget, $ExtContent, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "[반영 완료] $ExtTarget" -ForegroundColor Green

# 3. student/appearance.json 반영
$AppTarget = Join-Path $OnClient "student\appearance.json"
$AppContent = @'
{
  "schema": "aleph.student.appearance.v1",
  "appName": "복수를결심한인공능지",
  "baseStarterName": "케셰브 (0.2.11)",
  "layoutType": "control-dashboard-4cards-and-trends",
  "packagingType": "basic-stage-then-inno-setup-user-install",
  "coreFeaturesOrder": [
    {
      "rank": 1,
      "id": "top-status-cards-4",
      "title": "핵심 기능 1 · 관제 대시보드 상단 상태 카드 4종 (SDP 연결 분리 · 기기/세션 · XDR 알림 · 내 PC 자원 요약)"
    },
    {
      "rank": 2,
      "id": "pc-resource-trend-comparator",
      "title": "핵심 기능 2 · 내 PC 상태(CPU·메모리·디스크) 일반 권한 측정 및 직전 측정 대비 추이 비교(Δ)·상태 해석기"
    },
    {
      "rank": 3,
      "id": "pc-security-posture-readonly",
      "title": "핵심 기능 3 · 이 PC의 네트워크 구성 · 방화벽 설정(읽기 전용) · Windows 기록(System·Application 최근 24시간 경고·오류 건수) 점검"
    }
  ],
  "badges": {
    "measured": "[실측값 · 내 PC]",
    "example": "[예시값 · 설명용(실제 조회 아님)]",
    "unverifiable": "[확인 불가]"
  },
  "constraints": {
    "requireAdmin": false,
    "firewallReadOnly": true,
    "eventLogDisclaimer": "이 건수는 일반 운영체제 로그 통계이며 침해나 공격 탐지 결과가 아닙니다.",
    "separateSdpFromLocalPc": true
  }
}

'@
[IO.File]::WriteAllText($AppTarget, $AppContent, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "[반영 완료] $AppTarget" -ForegroundColor Green

# 4. docs/STUDENT_RUNBOOK.md 반영
$RunbookTarget = Join-Path $OnClient "docs\STUDENT_RUNBOOK.md"
$RunbookContent = @'
# 복수를결심한인공능지 (케셰브 ZTNA & XDR 보안 Agent) — 실행 설명서 및 시스템 구성도

- **문서 목적**: 처음 보는 사람도 이 설명서만 보고 `C:\choi-bujang-secret-vault-main\on-client` 앱을 설치·실행·종료·재실행하고, 관제 대시보드형 화면과 핵심 기능 3가지를 확인할 수 있도록 안내합니다.
- **앱 이름**: **복수를결심한인공능지** (제공 시작 틀 기본 이름: **케셰브 `0.2.11`**, 서버 진단 메타 버전: `0.1.0`)
- **보존 원칙**: 기존 1~3차 프로젝트 폴더(`C:\choi-bujang-secret-vault-main`)와 이미 제출한 산출물은 지우거나 옮기지 않고 그대로 보존합니다.

## 1. 제공 기능과 내가 만든(바꾼) 기능의 구분

| 구분 | 파일 경로 (`on-client` 기준) | 담당 역할 및 내용 |
|---|---|---|
| **제공 공통 기능**<br>(원본 계약 유지) | `public/index.html`<br>`public/app.js`<br>`public/style.css`<br>`public/ai-connect.mjs`<br>`public/vulnerabilities-view.mjs`<br>`src/server.mjs` (기본 API)<br>`tools/start-alekov.ps1` | • 상단 상태 배지(`mode-badge`), 좌측 3개 메뉴 탭(`보호 현황`·`업무 앱`·`보안 기록`), `다시 불러오기`, `도움정보 불러오기` 버튼<br>• `GET /api/diagnostics`의 기본 7개 필드(`requestId`, `component`, `version`, `engine.mode`, `engine.code`, `ai`, `checkedAt`) 제공<br>• 13~20단계 학생 슬롯(`student-identity`, `student-status`, `student-decision`, `student-events`, `student-explanation`, `student-action`, `student-ai-connection`, `student-vulnerabilities`) 호출 |
| **내가 만든·다듬은 기능 1**<br>(관제 대시보드 틀 + 핵심 3기능 우선 배치) | `student/extension.mjs`<br>`student/appearance.json` | • 화면 맨 위에 **관제 대시보드 상단 상태 카드 4종**(① SDP 서버 연결 상태 분리 카드, ② 기기·세션 보안 카드, ③ 내 PC 자원 요약 카드, ④ 내 PC 방화벽·Windows 기록 요약 카드)과 아래 **추이·기록 영역**을 배치<br>• **「내 PC 상태·보안 구성 다시 조회」 버튼**과 실시간 **대기 표시(`⏳ 조회 대기 중…`)**, 키보드(`Tab`·`Enter`·`Space`) 접근성 지원<br>• `student/extension.mjs` 내 중복 선언되어 있던 `renderVulnerabilities` 함수를 단일 정의로 정리 |
| **내가 만든·다듬은 기능 2**<br>(내 PC 자원 실측 + 직전 측정 대비 추이 비교·해석) | `student/extension.mjs`<br>(`src/server.mjs` 진단 확장 연동) | • 제공 `GET /api/diagnostics`의 `checkedAt` 근거를 재사용하여, 일반 사용자 권한(`node:os`, `fs.statfs`)으로 읽은 **CPU 사용률(`%`, 코어 수)**, **메모리 사용량(`GiB`, `%`)**, **디스크 남은 공간(`GiB`, `%`)**을 측정 시각·단위와 함께 표시<br>• 2회 이상 조회 시 **직전 측정 시각 대비 변화량(Δ `%p`, `±GiB`)**과 **임계치 기반 상태 해석(`자원 여유(정상)` / `주의`)** 자동 표시<br>• 아직 조회하지 않았거나 읽지 못한 값은 예시 숫자로 꾸미지 않고 **`[확인 불가]`와 구체적인 이유**를 표시 |
| **내가 만든·다듬은 기능 3**<br>(네트워크 · 방화벽 읽기 전용 · Windows 기록 건수) | `student/extension.mjs`<br>(`src/server.mjs` 진단 확장 연동) | • 일반 권한 읽기 전용으로 **활성 네트워크 인터페이스(IPv4·넷마스크)**, **Windows 방화벽 프로필 상태(Domain·Private·Public 켜짐/꺼짐, 설정 변경 절대 없음)**, **최근 24시간 Windows 기록(`System`·`Application`) 경고·오류 건수** 표시<br>• 화면에 **「이 건수는 일반 운영체제 로그 통계이며 침해나 공격 탐지 결과가 아닙니다」** 및 **「SDP 미연결 상태는 로컬 PC 조회 성공과 별개입니다」**를 명시 |

## 2. 시스템 구성도

```mermaid
flowchart TD
  Browser["PC 브라우저 (http://127.0.0.1:5189/)\n제공 화면: public/index.html · public/app.js · public/style.css"]
  StudentUI["학생 관제 대시보드 & 핵심 기능 3종\non-client/student/extension.mjs · student/appearance.json"]
  LocalServer["로컬 앱 서버 (Node.js 22~24, 기본 24.19.0)\non-client/src/server.mjs (127.0.0.1:5189)"]
  PcProbe["일반 권한 내 PC 상태·보안 구성 읽기 (읽기 전용)\nCPU·메모리·디스크(statfs)·네트워크·방화벽·Windows 기록"]
  Adapter["학생 엔진 어댑터\non-client/student/engine-adapter.mjs (기본: SDP 미연결 disconnected)"]
  SdpHost["기존 SDP/XDR 호스트\non-client/src/engine/sdp-host.mjs (-SdpHostConfig 지정 시에만)"]
  AiGate["CLCO 수업용 AI 게이트\non-client/src/ai/ · src/connection/ (-NativeHostConfig 및 승인 시에만)"]
  OsvScan["설치 패키지 OSV 조회기\non-client/src/vulnerabilities/project-scan.mjs"]

  Browser -->|렌더링 호출| StudentUI
  Browser -->|HTTP GET/POST /api/*| LocalServer
  LocalServer -->|GET /api/diagnostics| PcProbe
  LocalServer --> Adapter
  Adapter -. "-SdpHostConfig 지정 시" .-> SdpHost
  LocalServer -. "AI 연결 승인 시" .-> AiGate
  LocalServer -->|GET /api/vulnerabilities| OsvScan
```

## 3. 처음 보는 사람을 위한 설치·실행·종료·재실행 순서

### 3.1 사전 준비 확인
1. **Windows PowerShell**(일반 사용자 권한 창, 관리자 권한 불필요)을 엽니다.
2. **Node.js 버전(`22`~`24`, 권장 `v24.19.0`)**을 확인합니다.
   ```powershell
   node --version
   ```
   - `v18.x` 이하 버전이면 `node:sqlite` 모듈을 찾지 못해 서버가 켜지지 않습니다. 반드시 Node.js `22`~`24`(`v24.19.0`)를 사용하세요.
3. **작업 폴더 위치 확인**:
   - 프로젝트 최상위 폴더(`C:\choi-bujang-secret-vault-main`)가 아니라, 그 안의 **`on-client` 앱 폴더**(`C:\choi-bujang-secret-vault-main\on-client`)에서 실행해야 합니다.
   - `on-client/package.json`에는 외부 npm 의존성이 없으므로 **`npm install`을 실행하지 않습니다.**

### 3.2 앱 실행하기
```powershell
cd C:\choi-bujang-secret-vault-main\on-client
npm run check
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1
```
- PowerShell 창에 아래 두 줄이 나타나면 정상 기동된 것입니다.
  ```text
  케셰브가 켜졌습니다. 브라우저에서 http://127.0.0.1:5189/ 을 여세요.
  서버가 응답한 것만 확인했습니다. AI 연결 상태는 화면에서 따로 확인해 주세요.
  ```
- 예제 자료(demo) 모드로 화면을 보려면 `-Demo` 옵션을 붙입니다(실제 SDP 연결 아님):
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1 -Demo
  ```

### 3.3 종료 및 다시 실행하기
- **종료**: 서버가 켜진 PowerShell 창에서 `Ctrl+C`를 누릅니다.
- **다시 실행**: 같은 `C:\choi-bujang-secret-vault-main\on-client` 폴더에서 위 실행 명령을 다시 입력합니다.

## 4. 자주 막히는 단계와 오류 문구별 원인·해결 안내

다른 사람이 실행 안내를 따라 하다가 막혔을 때 원인이 **안내(실행 위치·환경)**에 있는지 **코드**에 있는지 바로 판별하는 표입니다.

| 막힌 단계 및 오류 문구 | 원인 구분 (안내 vs 코드) | 정확한 원인 설명 | 해결 방법 (필요한 조치) |
|---|---|---|---|
| `앱 폴더가 아닙니다` 또는 `-File 매개 변수에 대한 인수 '.\tools\start-alekov.ps1'이(가) 없습니다.` | **안내(작업 폴더 위치)** | 상위 폴더(`C:\choi-bujang-secret-vault-main`)에서 명령을 실행했기 때문입니다. | `cd C:\choi-bujang-secret-vault-main\on-client`로 이동한 뒤 실행합니다. |
| `Error [ERR_UNKNOWN_BUILTIN_MODULE]: No such built-in module: node:sqlite` 또는 `지금 Node.js 는 vXX 입니다` | **안내(Node.js 버전 환경)** | 제공 코드(`src/actions/store.mjs`)가 Node.js 22.5+ 내장 `node:sqlite`를 쓰는데, PC의 기본 Node.js가 18·20 버전일 때 발생합니다. | Node.js `24.19.0`(또는 22~24)을 설치하고 **새 PowerShell 창**을 열어 실행합니다. |
| `포트 5189 를 다른 프로그램이 쓰고 있습니다` | **안내(포트 중복 실행)** | 이전에 켜 둔 앱 서버 창이 아직 켜져 있거나 다른 프로세스가 5189 포트를 사용 중입니다. | 기존 프로그램을 강제 종료하지 말고 명령 끝에 `-Port 5190`을 붙여 실행한 뒤 `http://127.0.0.1:5190/`으로 접속합니다. |
| `'iscc' 용어가 cmdlet... 이름으로 인식되지 않습니다` | **안내(외부 설치 도구 미설치)** | Inno Setup(`ISCC.exe`)은 기본 시작 틀에 내장된 도구가 아니며 Windows PATH에 없을 때 발생합니다. | 기본 앱 실행·제출에는 `iscc`가 필요하지 않습니다. 설치 파일(`setup.exe`)을 만들 때만 `winget install --id JRSoftware.InnoSetup -e --scope user` 설치 후 전체 경로로 실행합니다. |
| 화면에 `ENGINE_NOT_CONNECTED (연결 없음)` 표시 | **정상 동작 (오류 아님)** | 기본 실행에서는 개인 SDP 설정(`-SdpHostConfig`)이 없으므로 `SDP 미연결`로 나오는 것이 정상입니다. | 내 PC 상태 실측은 **「내 PC 상태·보안 구성 다시 조회」**(또는 `도움정보 불러오기`) 버튼을 눌러 따로 확인합니다. |

'@
[IO.File]::WriteAllText($RunbookTarget, $RunbookContent, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "[반영 완료] $RunbookTarget" -ForegroundColor Green

# 5. docs/DEMO_AND_FINAL_SUMMARY.md 반영
$DemoTarget = Join-Path $OnClient "docs\DEMO_AND_FINAL_SUMMARY.md"
$DemoContent = @'
# 복수를결심한인공능지 — 완성본 시연 순서 · 기능 구분 · 한계 및 제출 정리서

- **프로젝트 경로**: `C:\choi-bujang-secret-vault-main` (앱 실행 경로: `C:\choi-bujang-secret-vault-main\on-client`)
- **원격 GitHub 저장소**: `https://github.com/wonq-Port/choi-bujang-secret-vault.git`
- **작성 기준일**: 2026-10-29 (KST)
- **원칙**: 확인하지 않은 기능이나 미연결 원천(SDP·CLCO·실제 조치 집행)을 성공이나 완료(`v1.0`)로 적지 않으며, 내 PC에서 실제로 잰 값(`[실측값 · 내 PC]`)과 설명용 예시 값(`[예시값 · 설명용]`)을 명확히 분리합니다.

## 1. 제공 기능과 내가 만든 기능의 구분

| 구분 | 항목 | 관련 파일 | 비고 |
|---|---|---|---|
| **제공 기능**<br>(수업 시작 틀 `0.2.11` 제공) | • 3대 메뉴 탭(`보호 현황`, `업무 앱`, `보안 기록`) 및 공통 카드 레이아웃<br>• 로컬 HTTP 서버(`127.0.0.1:5189`) 및 기본 API(`/api/me`, `/api/apps`, `/api/access`, `/api/events`, `/api/devices`, `/api/sessions`, `/api/diagnostics`, `/api/vulnerabilities`)<br>• 계정 연결 확인(native) 및 AI 앱 승인·점검 공통 UI(`public/ai-connect.mjs`) | `public/index.html`<br>`public/app.js`<br>`public/style.css`<br>`src/server.mjs` | 제공 공통 파일은 학생 성취로 계산하지 않으며 기존 계약을 그대로 유지함 |
| **내가 만든 기능 1**<br>(관제 대시보드 상단 카드 4종 & 수동 재조회·키보드 지원) | • 맨 위 **상태 카드 4종**(① SDP 서버 연결 상태 분리, ② 기기·세션 보안, ③ 내 PC 자원 요약, ④ 내 PC 방화벽·Windows 기록 요약) + 아래 **추이와 기록** 배치<br>• **「내 PC 상태·보안 구성 다시 조회」 버튼** 및 **대기 표시(`⏳ 조회 대기 중…`)**, 실패 시 다음 행동 안내, 키보드(`Tab`·`Enter`·`Space`) 조작 지원<br>• `student/extension.mjs` 내 중복 `renderVulnerabilities` 정의 제거 및 단일화 | `student/extension.mjs`<br>`student/appearance.json` | 제공 화면과 겹치는 버튼을 중복 생성하지 않고 내가 추가한 관제 영역만 제어 |
| **내가 만든 기능 2**<br>(내 PC 상태 실측 및 직전 측정 대비 추이 비교·해석) | • 제공 `GET /api/diagnostics`의 `checkedAt` 시각 근거를 재사용해 일반 권한으로 **CPU 사용률(`%`, 코어 수)**, **메모리 사용량(`GiB`, `%`)**, **디스크 남은 공간(`GiB`, `%`)** 실측<br>• 2회 이상 조회 시 **직전 측정 대비 증감(Δ `%p`, `±GiB`)** 및 **임계치 기반 자동 상태 해석(`자원 여유(정상)` / `주의`)** 표시 | `student/extension.mjs`<br>`src/server.mjs` (선택적 로컬 진단 확장 시) | 모든 수치에 **측정 시각 + 단위 + `[실측값 · 내 PC]` 배지** 표시 |
| **내가 만든 기능 3**<br>(내 PC 네트워크·방화벽 읽기 전용·Windows 기록 건수) | • 일반 권한 읽기 전용으로 **활성 네트워크 구성(IPv4·넷마스크)**, **Windows 방화벽 프로필 상태(읽기 전용, 변경 없음)**, **최근 24시간 Windows 기록(`System`·`Application`) 경고·오류 건수** 표시<br>• **「침해나 공격 탐지 결과가 아님」** 경고 배너 및 **「SDP 미연결과 로컬 PC 조회 성공 분리」** 명시 | `student/extension.mjs`<br>`src/server.mjs` (선택적 로컬 진단 확장 시) | 관리자 권한이 필요한 항목은 권한 상승 없이 **`[확인 불가]`와 사유**로 표시 |

## 2. 핵심 기능 3가지를 보여 주는 완성본 시연 순서 (5분 시연 시나리오)

1. **사전 상태 및 서버 기동 시연 (PowerShell)**
   - `C:\choi-bujang-secret-vault-main\on-client`에서 `npm run check`로 문법 이상 없음을 먼저 보여 줍니다.
   - `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1`로 앱을 켜고 `http://127.0.0.1:5189/`를 엽니다.
2. **시연 1 — 관제 대시보드 상단 상태 카드 4종 & 조회 전 ‘확인 불가’ 정직성 확인 (핵심 기능 1)**
   - `보호 현황` 탭의 `학생 상태·알림 표시` 칸 맨 위에 **관제 대시보드 상단 상태 카드 4개**가 먼저 보이는지 확인합니다.
   - 아직 조회 버튼을 누르기 전이므로 카드 ①에는 **`[SDP 미연결 · ENGINE_NOT_CONNECTED]`**가 표시되고, 카드 ③·④에는 가짜 예시 숫자가 아닌 **`[확인 불가 · 측정 전]`**과 사유가 표시됨을 보여 줍니다.
3. **시연 2 — 키보드 조작으로 「내 PC 상태·보안 구성 다시 조회」 1차·2차 실행 및 추이 비교 확인 (핵심 기능 2)**
   - 마우스 없이 `Tab` 키로 **「내 PC 상태·보안 구성 다시 조회」** 버튼에 초점(노란 포커스 링)을 맞춘 뒤 `Enter`(또는 `Space`)를 누릅니다.
   - 버튼 옆에 **`⏳ 대기 표시`**가 뜬 뒤, 1차 실측값(**CPU `%`, 메모리 `GiB`/`%`, 디스크 남은 공간 `GiB`/`%`**)이 **측정 시각(KST·ISO)** 및 **`[실측값 · 내 PC]`** 배지와 함께 나타나는 것을 보여 줍니다.
   - 2~3초 뒤 같은 버튼을 한 번 더 눌러 **직전 측정 시각 대비 변화량(`CPU ±%p`, `메모리 ±GiB`, `디스크 ±GiB`)과 상태 해석 문장**이 실시간으로 계산되는 것을 보여 줍니다.
4. **시연 3 — 내 PC 네트워크·방화벽(읽기 전용)·Windows 기록 건수 및 침해 비탐지 고지 확인 (핵심 기능 3)**
   - 바로 아래 **핵심 기능 3** 패널에서 노란색 안내 배너(**「이 건수는 일반 운영체제 이벤트 통계이며 침해나 공격 탐지 결과가 아닙니다 · 방화벽 읽기 전용 · SDP 미연결과 별개」**)를 짚어 줍니다.
   - 일반 권한으로 읽은 **활성 네트워크 인터페이스**, **방화벽 프로필(Domain/Private/Public 켜짐 여부)**, **최근 24시간 System·Application 경고·오류 건수**(또는 일반 권한 제한 시 `확인 불가`와 사유)를 보여 줍니다.
5. **시연 4 — 탭 이동(업무 앱 · 보안 기록) 및 종료·재실행 확인**
   - 좌측 메뉴에서 방향키(`↓`)로 `업무 앱`, `보안 기록` 탭으로 이동해 하단 추이·기록 패널에서도 **`[SDP 미연결]`**과 **`[예시값 · 설명용]`**이 명확히 구분되는지 보여 줍니다.
   - PowerShell 창에서 `Ctrl+C`로 종료한 뒤 다시 켜도 동일하게 동작함을 확인합니다.

## 3. 아직 안 되거나 ‘확인 불가(UNV)’로 남은 한계

확인하지 않았거나 운영 원천이 연결되지 않은 항목은 성공으로 적지 않고 아래와 같이 한계로 구분합니다.

| 항목 | 현재 상태 | 구체적 이유 및 한계 설명 |
|---|---|---|
| **실제 SDP 호스트 및 사내 업무 앱 판정** | **SDP 미연결 (`disconnected`)** | 운영자가 발급한 개인 인증서·토큰 설정 파일(`-SdpHostConfig`)이 없으므로 실제 SDP 서버 연결은 `ENGINE_NOT_CONNECTED` 상태입니다. (로컬 PC 상태 조회 성공을 SDP 연결로 치환하지 않음) |
| **CLCO 수업용 AI 연결 및 사건 설명** | **기다림 (`UNV` · 미연결)** | `-NativeHostConfig` 및 운영자 앱 권한 승인 전이므로 실제 AI 모델 목록 조회(17단계)와 실제 사건 설명(18단계)은 실행되지 않습니다. |
| **보안 조치 실제 원천 집행 (19단계)** | **미지원 (`UNV`)** | 현재 기록의 `supportedActions`가 빈 배열(`[]`)이며, 실제 세션 회수·기기 차단 원천 집행기는 연결되지 않았습니다. |
| **설치 패키지 공개 취약점(OSV) 실측 대조 (20단계)** | **미설정 (`not_configured` / `unverifiable`)** | `on-client`는 외부 의존성이 `0`개라 `package-lock.json`이 없고 승인 패키지 목록이 비어 있어 실제 OSV 대조 결과는 생성되지 않습니다(취약점 없음으로 간주하지 않음). |
| **관리자 권한 전용 Windows 보안 로그(Security 채널 등)** | **확인 불가 (`unverifiable`)** | 관리자 권한 상승을 사용하지 않으므로, 일반 사용자 권한으로 접근이 거부되는 보안 채널이나 방화벽 세부 정책은 바꾸려 하지 않고 `확인 불가`와 사유로만 표시합니다. |
| **버전 표기 차이 및 릴리스 상태** | **검증 중 (`v1.0` 미부여)** | `on-client/package.json`(`0.2.11`), `FINAL_PRODUCT_GUIDE.md`(`0.2.9`), `/api/diagnostics`(`0.1.0`) 버전 표기가 서로 다르며, 19단계 원천 집행 연결 전이므로 `v1.0`으로 표시하지 않습니다. |

## 4. 실제로 확인한 근거 (화면 · 실행 기록 · 커밋 번호 기록란)

| 구분 | 항목 | 확인 결과 (내 PC 실측값 vs 설명용 예시값 구분) |
|---|---|---|
| **저장소 주소** | Git `origin` URL | `https://github.com/wonq-Port/choi-bujang-secret-vault.git` |
| **기존 최신 커밋 (21단계 저장점)** | 업로드된 원본 기준 SHA | `304a3e856f517126286b24c98486cf86bdeeacf3` (직전 단계 커밋: `a48874a`) |
| **마무리 제출 커밋 번호** | `git rev-parse HEAD` (40자리) | 새 커밋 후 아래 5장 명령으로 출력된 **내 PC 실측 40자리 SHA** 기록 |
| **문법 및 계약 검사** | `node --check` | **[실측값]** `student/extension.mjs` 및 `src/server.mjs` 문법 검사 통과 (ExitCode `0`) |
| **화면 확인 근거** | `http://127.0.0.1:5189/` | **[실측값]** 상단 상태 카드 4종, `내 PC 상태·보안 구성 다시 조회` 버튼 및 대기 표시, CPU·메모리·디스크 실측 및 직전 대비 추이(Δ), 네트워크·방화벽(읽기 전용)·Windows 기록 건수 및 비침해 고지 문구 확인 |

## 5. 마무리 제출용 Git 커밋 및 GitHub 업로드(push) 순서

포장 명령(`npm run package-app`)이나 새 포장 스크립트는 실행하지 않고, 수정된 소스·문서만 확인하여 안전하게 커밋·푸시하는 절차입니다.

```powershell
# 1) 최상위 프로젝트 폴더로 이동 및 바뀐 파일 확인
cd C:\choi-bujang-secret-vault-main
git status --short
git diff --stat

# 2) 제출 대상 파일만 스테이징 (비밀 파일·임시 폴더 제외)
git add on-client/student/extension.mjs on-client/student/appearance.json on-client/docs/STUDENT_RUNBOOK.md on-client/docs/STUDENT_REPRODUCTION_RECORD.md on-client/docs/DEMO_AND_FINAL_SUMMARY.md

# (선택: 1단계 로컬 PC 실측을 위해 on-client/src/server.mjs 도 함께 반영한 경우에만 추가)
# git add on-client/src/server.mjs

# 3) 스테이징된 목록 확인 후 커밋
git diff --cached --name-status
git commit -m "보안 Agent 관제 대시보드 및 내 PC 상태·문서 정리"

# 4) 원격 저장소 주소와 40자리 커밋 번호(HEAD) 확인
git remote get-url origin
git rev-parse HEAD

# 5) GitHub에 업로드 (절대 --force 를 쓰지 않음)
git push origin main
```

### ⚠️ 만약 `git push origin main`이 거절(rejected)될 때의 원인과 해결 순서
- **절대 `git push --force`로 덮어쓰지 마세요.** 기존 제출 기록이 사라질 수 있습니다.
- **거절 원인 1 (`non-fast-forward` / `fetch first`)**: GitHub 웹 화면(`Add files via upload` 등)에서 직접 올린 커밋(`304a3e8` 등)이 내 PC 로컬 브랜치에 아직 반영되지 않았을 때 발생합니다.
  - **해결**: `git fetch origin` → `git status`로 차이를 확인한 뒤 `git pull --rebase origin main`으로 원격 기록을 먼저 이어 붙이고 다시 `git push origin main`을 실행합니다.
- **거절 원인 2 (`Authentication failed` / `403`)**: Windows 자격 증명 관리자에 다른 GitHub 계정이 들어 있거나 토큰 권한이 만료된 경우입니다.
  - **해결**: GitHub 로그인 창에서 `wonq-Port` 계정으로 다시 인증한 뒤 `git push origin main`을 실행합니다.

'@
[IO.File]::WriteAllText($DemoTarget, $DemoContent, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "[반영 완료] $DemoTarget" -ForegroundColor Green

# 6. (선택) src/server.mjs 로컬 PC 상태 실측 확장 반영 (-IncludeServerTelemetry 옵션 지정 시에만)
if ($IncludeServerTelemetry) {
  $SrvTarget = Join-Path $OnClient "src\server.mjs"
  $SrvBackup = Join-Path $OnClient "src\server.backup-original.mjs"
  if ((Test-Path -LiteralPath $SrvTarget) -and -not (Test-Path -LiteralPath $SrvBackup)) {
    Copy-Item -LiteralPath $SrvTarget -Destination $SrvBackup -Force
    Write-Host "[원본 보존] src\server.mjs -> src\server.backup-original.mjs 백업 완료" -ForegroundColor Green
  }
  $SrvContent = @'
import http from 'node:http';
import {readFile,statfs} from 'node:fs/promises';
import os from 'node:os';
import {execFile} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {AsyncLocalStorage} from 'node:async_hooks';
import {types} from 'node:util';
import {createActionService} from './actions/service.mjs';
import {createSdpActionConfiguration} from './actions/sdp-action-engine.mjs';
import {readActionStartupConfiguration} from './actions/action-startup-config.mjs';
import {engineMethod,engineError,loadEngine,demoEngine} from './engine.mjs';
import {readSdpHostConfiguration} from './engine/sdp-host-config.mjs';
import {createSdpHostEngine,isOwnedSdpHostEngine,openSdpIncidentOperation,readSdpIncidentOperation,assertSdpIncidentOperation,closeSdpIncidentOperation} from './engine/sdp-host.mjs';
import {createOnAiService,validateLearnerSupportGuide} from './ai/service.mjs';
import {prepareLearnerSupportRequest} from './ai/learner-support-contract.mjs';
import {createVaultOnAiService} from './ai/vault-service.mjs';
import {createConnectionManager} from './connection/manager.mjs';
import {createProjectScanner} from './vulnerabilities/project-scan.mjs';
import {buildLocalLearnerSupportGuide,isLearnerSupportProblemKind,readLocalLearnerSupportObservation} from './learner-support/service.mjs';
import {nativeOwn,nativePublicError} from './connection/native-login.mjs';
import {createNativeHostContext,captureNativeHostConfiguration,readNativeHostConfiguration,openNativeHostOperation,readNativeHostOperation,assertNativeHostOperation,createNativeOperationVault,closeNativeHostOperation} from './connection/native-context.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
const id=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/.test(value);
const record=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const text=value=>typeof value==='string'&&value.length<=2000;
const files=new Map([['/','public/index.html'],['/index.html','public/index.html'],['/app.js','public/app.js'],['/style.css','public/style.css'],['/vulnerabilities-view.mjs','public/vulnerabilities-view.mjs'],['/student/extension.mjs','student/extension.mjs'],
  ['/ai-connect.mjs','public/ai-connect.mjs'],
  ...['alekov-ai-explain','alekov-app-icon','alekov-connect-approval','alekov-connection-unknown','alekov-empty-records'].map(name=>[`/assets/alekov/${name}.webp`,`public/assets/alekov/${name}.webp`])]);
const connectionRoutes=new Map(['start','finish','status','cancel'].map(kind=>[`/api/ai/connect/${kind}`,kind]));
const safeErrors=Object.freeze({
  ENGINE_NOT_CONNECTED:[503,'기존 서버·에이전트의 연결을 확인할 수 없습니다. 연결 어댑터를 먼저 확인하세요.'],
  ENGINE_ADAPTER_INVALID:[503,'기존 서버 연결 어댑터의 형식을 확인하세요.'],
  ENGINE_RESULT_UNVERIFIED:[503,'서버 응답을 확인할 수 없습니다. 정상으로 판단하지 말고 연결 계약을 확인하세요.'],
  ENGINE_TIMEOUT:[503,'기존 서버의 응답 시간이 초과됐습니다. 다시 확인하세요.'],
  SUBJECT_SCOPE_UNVERIFIED:[503,'현재 로그인과 사건·프로젝트의 연결을 확인할 수 없습니다.'],
  JSON_REQUIRED:[415,'JSON 요청 형식을 확인하세요.'],REQUEST_TOO_LARGE:[413,'요청이 너무 큽니다.'],
  INVALID_JSON:[400,'요청 형식을 확인하세요.'],REQUEST_INVALID:[400,'요청에 필요한 항목만 보내세요.'],
  HOST_REJECTED:[403,'로컬 실행 주소를 확인하세요.'],QUERY_REJECTED:[400,'지원하지 않는 요청입니다.'],
  ORIGIN_REJECTED:[403,'앱 화면에서 다시 요청하세요.'],EVENT_NOT_FOUND:[404,'본인 기록에서 사건을 찾을 수 없습니다.'],
  APP_NOT_FOUND:[404,'업무 앱을 찾을 수 없습니다.'],
  REQUEST_CANCELLED:[499,'연결이 종료되어 요청을 취소했습니다.'],
  REQUEST_TIMEOUT:[503,'요청 처리 시간이 초과됐습니다. 연결 상태를 확인한 뒤 다시 시도하세요.'],
  ON_AI_PROVISIONING_PENDING:[503,'학생 앱의 현재 계정 연결과 앱 전용 AI 이용 권한을 담당자에게 확인하세요.'],
  SERVICE_UNAVAILABLE:[503,'연결 상태를 확인할 수 없습니다. 잠시 후 다시 시도하세요.'],
});
const aiErrorMessages=Object.freeze({
  ON_AI_PROVISIONING_PENDING:'학생 앱의 현재 계정 연결과 앱 전용 AI 이용 권한을 담당자에게 확인하세요.',
  MODEL_NOT_CONFIGURED:'앱 서버에 허용된 AI 모델을 설정하세요.',
  ON_AI_AUTHORIZATION_CHANGED:'AI 이용 권한 내용이 점검 도중 바뀌었습니다. 다시 점검하기 전에 담당자에게 현재 권한을 확인하세요.',
  ON_AI_MODEL_LIST_EMPTY:'현재 앱 권한으로 쓸 수 있는 AI 모델이 없습니다. 담당자에게 모델 허용 설정을 확인하세요.',
  ON_AI_INVALID_INPUT:'사건의 근거와 현재 상태를 확인하세요.',ON_AI_INVALID_OUTPUT:'AI 설명의 근거와 형식을 확인할 수 없습니다.',
  ON_AI_TRANSPORT_PENDING:'공통 AI 연결을 준비 중입니다.',
  WB_CLCO_AUTH_REQUIRED:'앱 전용 열쇠를 확인하세요.',WB_CLCO_ACCESS_BLOCKED:'학생 앱의 이용 권한을 담당자에게 확인하세요.',
  WB_CLCO_SESSION_CLOSED:'현재 AI 이용 시간을 확인하세요.',WB_CLCO_COHORT_BUDGET_EXHAUSTED:'반의 AI 사용량을 담당자에게 확인하세요.',
  WB_CLCO_RATE_LIMITED:'AI 요청이 잠시 제한됐습니다.',WB_CLCO_LIMIT_REACHED:'AI 이용 한도를 확인하세요.',
  WB_CLCO_SERVER_UNAVAILABLE:'AI 서버가 응답하지 않습니다.',WB_CLCO_TIMEOUT:'AI 요청 시간이 초과됐습니다.',
  WB_CLCO_NETWORK_ERROR:'AI 서버 연결을 확인하세요.',WB_CLCO_CANCELLED:'AI 요청을 취소했습니다.',
  WB_CLCO_INVALID_URL:'AI 서버 주소를 확인하세요.',WB_CLCO_INVALID_TOKEN:'앱 전용 열쇠 형식을 확인하세요.',
  WB_CLCO_INVALID_LIMIT:'AI 요청 제한 시간을 확인하세요.',WB_CLCO_INVALID_RESPONSE:'AI 서버 응답을 확인할 수 없습니다.',
  WB_CLCO_INVALID_CONTENT_TYPE:'AI 서버 응답 형식을 확인하세요.',WB_CLCO_RESPONSE_TOO_LARGE:'AI 서버 응답이 너무 큽니다.',
  WB_CLCO_REDIRECT_BLOCKED:'AI 서버 주소가 다른 곳으로 이동했습니다.',WB_CLCO_REQUEST_FAILED:'AI 요청을 처리하지 못했습니다.',
});
// native /api/ai/check 응답의 retryable: 기다리거나 다시 요청하면 풀릴 수 있다고 원인이 확인된 것만 true.
// 권한·구성·검증 불가(PENDING)·허용 밖 모델·응답 계약 위반·원인 불명은 false(자동 재시도는 어디서도 하지 않는다).
const AI_RETRYABLE=new Set(['WB_CLCO_RATE_LIMITED','WB_CLCO_SERVER_UNAVAILABLE','WB_CLCO_TIMEOUT','WB_CLCO_NETWORK_ERROR','WB_CLCO_CANCELLED','REQUEST_TIMEOUT','REQUEST_CANCELLED']);
const exact=(value,keys)=>record(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const uuid=value=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
const confirmation=value=>typeof value==='string'&&/^ac-on-[A-Za-z0-9_-]{43}$/.test(value);
const actionErrors=Object.freeze({
  ACTION_UNSUPPORTED:[503,'현재 원천 서버의 조치 연결과 권한 확인을 지원하지 않습니다.'],
  ACTION_INPUT_INVALID:[400,'조치 요청 항목을 확인하세요.'],ACTION_SCOPE_UNVERIFIED:[403,'현재 사용자와 조치 권한의 연결을 확인할 수 없습니다.'],
  ACTION_SCOPE_CHANGED:[403,'사용자·프로젝트·세션 또는 권한이 변경됐습니다. 현재 기록에서 다시 확인하세요.'],
  ACTION_EVENT_UNAVAILABLE:[404,'현재 본인 기록에서 사건을 확인할 수 없습니다.'],ACTION_DENIED:[403,'현재 원천 정책이 이 조치를 허용하지 않습니다.'],
  ACTION_SNAPSHOT_CHANGED:[409,'사건의 대상·근거·상태가 변경됐습니다. 다시 준비하고 확인하세요.'],
  ACTION_CONFIRMATION_INVALID:[400,'이 조치의 확인 정보를 확인하세요.'],ACTION_CONFIRMATION_EXPIRED:[409,'조치 확인 시간이 지났습니다. 다시 준비하세요.'],
  ACTION_STORE_FAILED:[503,'조치 기록을 확인할 수 없습니다. 자동 집행하지 말고 결과를 확인하세요.'],
  ACTION_TIMEOUT:[503,'조치 결과를 확인하지 못했습니다. 효과가 없다고 판단하지 말고 결과만 다시 조회하세요.'],
  ACTION_CANCELLED:[499,'요청이 취소됐습니다. 이미 전달된 조치의 결과는 별도로 확인하세요.'],
  ACTION_RESULT_UNVERIFIED:[503,'조치 처리 결과를 확인할 수 없습니다. 정상 처리로 판단하지 마세요.'],
});
function projectAction(output,method,input) {
  if(output?.ok!==true){
    const code=Object.hasOwn(actionErrors,output?.error?.code)?output.error.code:'ACTION_RESULT_UNVERIFIED';
    const [status,message]=actionErrors[code];return {status,body:{ok:false,error:{code,message,retryable:false}}};
  }
  const d=output.data;
  if(!record(d)||!uuid(d.requestId)||!['prepared','pending','succeeded','denied','failed','unknown'].includes(d.status)
    ||method!=='prepare'&&d.requestId!==input.requestId)throw engineError('SERVICE_UNAVAILABLE','');
  const data={requestId:d.requestId,status:d.status};
  if(d.receiptId!==undefined){
    if(!uuid(d.receiptId)||!id(d.eventId)||!id(d.actionId)||!Number.isSafeInteger(d.version)||d.version<=0||typeof d.replayed!=='boolean')throw engineError('SERVICE_UNAVAILABLE','');
    Object.assign(data,{receiptId:d.receiptId,eventId:d.eventId,actionId:d.actionId,version:d.version,replayed:d.replayed});
  }else if(d.status!=='unknown')throw engineError('SERVICE_UNAVAILABLE','');
  if(method==='prepare'){
    if(d.status!=='prepared'||d.eventId!==input.eventId||d.actionId!==input.actionId||!confirmation(d.confirmationId)
      ||typeof d.confirmationExpiresAt!=='string'||!Number.isFinite(Date.parse(d.confirmationExpiresAt))||!exact(d.target,['id','generation'])
      ||typeof d.target.id!=='string'||!/^(?:device|subject):[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/.test(d.target.id)
      ||!Number.isSafeInteger(d.target.generation)||d.target.generation<=0)throw engineError('SERVICE_UNAVAILABLE','');
    Object.assign(data,{confirmationId:d.confirmationId,confirmationExpiresAt:d.confirmationExpiresAt,target:{id:d.target.id,generation:d.target.generation}});
  }
  if(d.observation!==undefined){
    if(!exact(d.observation,['observedAt','effectApplied'])||typeof d.observation.observedAt!=='string'||!Number.isFinite(Date.parse(d.observation.observedAt))
      ||typeof d.observation.effectApplied!=='boolean'||d.status==='succeeded'&&d.observation.effectApplied!==true)throw engineError('SERVICE_UNAVAILABLE','');
    data.observation={observedAt:d.observation.observedAt,effectApplied:d.observation.effectApplied};
  }
  if(d.status==='succeeded'&&!data.observation)throw engineError('SERVICE_UNAVAILABLE','');
  if(d.superseded===true&&d.status==='unknown')data.superseded=true;
  return {status:200,body:{ok:true,data}};
}
const opaque=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(value);
const canonicalSubject=value=>typeof value==='string'&&value.length>0&&value.length<=200&&value===value.trim()&&!/[\u0000-\u001f\u007f]/.test(value);
const AI_BINDING_KEYS=['schema','sourceSubjectId','canonicalStudentId','alephUserId','siteId','identityVersion','projectId','sessionId'];
function assertAiBinding(binding,source) {
  if(!exact(binding,AI_BINDING_KEYS)||binding.schema!=='aleph.on.ai-identity.v1'||!canonicalSubject(binding.canonicalStudentId)
    || !opaque(binding.alephUserId)||!opaque(binding.siteId)||!Number.isSafeInteger(binding.identityVersion)||binding.identityVersion<=0
    || binding.sourceSubjectId!==source.sourceSubjectId||binding.projectId!==source.projectId||binding.sessionId!==source.sessionId)
    throw engineError('ON_AI_PROVISIONING_PENDING','');
  return Object.freeze({...binding});
}
function aiFailure(output) {
  const code=Object.hasOwn(aiErrorMessages,output?.error?.code)?output.error.code:'WB_CLCO_REQUEST_FAILED';
  return {code,message:aiErrorMessages[code],retryable:true};
}
function aiHelp(output) {
  const value=output?.help;
  const allowed=['ON_AI_APP_AUTHORIZATION_VERIFIED','ON_AI_TEST_TRANSPORT_ONLY'];
  if(!record(value)||value.component!=='on-ai'||!allowed.includes(value.code)||typeof value.appCredentialsConfigured!=='boolean'
    || !['verified','pending'].includes(value.provisioning)||value.automaticRetries!==0||value.workbenchRequiredAtRuntime!==false)
    throw engineError('SERVICE_UNAVAILABLE','');
  if(output.audienceAuthorization==='verified'&&(value.code!=='ON_AI_APP_AUTHORIZATION_VERIFIED'||value.provisioning!=='verified')
    || output.audienceAuthorization==='test'&&(value.code!=='ON_AI_TEST_TRANSPORT_ONLY'||value.provisioning!=='pending'))throw engineError('SERVICE_UNAVAILABLE','');
  return {component:'on-ai',code:value.code,appCredentialsConfigured:value.appCredentialsConfigured,provisioning:value.provisioning,
    automaticRetries:0,workbenchRequiredAtRuntime:false};
}
function assertExplanation(explanation,event,secrets) {
  const safe=(value,max)=>typeof value==='string'&&value.trim().length>0&&value.length<=max
    && !/(?:Bearer\s+\S+|sk-(?:on-|proj-|ant-)?[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i.test(value)
    && !secrets.some(secret=>secret&&value.includes(secret));
  const evidenceIds=new Set(event.evidence.map(row=>row.id));
  const references=value=>Array.isArray(value)&&value.length>0&&new Set(value).size===value.length&&value.every(ref=>evidenceIds.has(ref));
  if(!exact(explanation,['summary','evidenceIds','proposals','requiresHumanConfirmation','executed'])||!safe(explanation.summary,1500)
    || explanation.requiresHumanConfirmation!==true||explanation.executed!==false||!references(explanation.evidenceIds)||explanation.evidenceIds.length!==evidenceIds.size
    || !Array.isArray(explanation.proposals)||explanation.proposals.length>3||explanation.proposals.some(row=>!exact(row,['action','evidenceIds','reason'])
      || !event.supportedActions.includes(row.action)||!references(row.evidenceIds)||!safe(row.reason,500)))throw engineError('SERVICE_UNAVAILABLE','');
  return {summary:explanation.summary,evidenceIds:[...explanation.evidenceIds],proposals:explanation.proposals.map(row=>({action:row.action,evidenceIds:[...row.evidenceIds],reason:row.reason})),requiresHumanConfirmation:true,executed:false};
}
function assertData(kind,data) {
  let valid=false;
  if(kind==='identity') valid=record(data)&&[data.user,data.device,data.session].every(row=>record(row)&&id(row.id))&&text(data.user.label)&&text(data.device.label)&&['compliant','noncompliant','unknown'].includes(data.device.status)&&['active','expired','revoked','unknown'].includes(data.session.status);
  if(kind==='apps') valid=Array.isArray(data)&&data.length<=100&&data.every(row=>record(row)&&id(row.id)&&text(row.name))&&new Set(data.map(row=>row.id)).size===data.length;
  if(kind==='decision') valid=record(data)&&id(data.appId)&&['allow','deny','challenge','unknown'].includes(data.decision)&&text(data.reason)&&Number.isFinite(Date.parse(data.checkedAt));
  if(kind==='events') valid=Array.isArray(data)&&data.length<=500&&data.every(row=>record(row)&&id(row.id)&&['access','xdr'].includes(row.kind)&&Number.isFinite(Date.parse(row.at))&&text(row.summary)&&Array.isArray(row.evidence)&&row.evidence.length<=20&&row.evidence.every(e=>record(e)&&id(e.id)&&text(e.text))&&Array.isArray(row.rules)&&row.rules.length<=20&&row.rules.every(r=>record(r)&&id(r.id)&&text(r.text))&&record(row.state)&&['allowed','denied','unknown'].includes(row.state.access)&&['active','expired','revoked','unknown'].includes(row.state.session)&&['compliant','noncompliant','unknown'].includes(row.state.device)&&Array.isArray(row.supportedActions)&&row.supportedActions.every(id))&&new Set(data.map(row=>row.id)).size===data.length;
  if(kind==='devices') valid=Array.isArray(data)&&data.length<=100&&data.every(row=>record(row)&&id(row.id)&&text(row.label)&&['compliant','noncompliant','unknown'].includes(row.status));
  if(kind==='sessions') valid=Array.isArray(data)&&data.length<=100&&data.every(row=>record(row)&&id(row.id)&&['active','expired','revoked','unknown'].includes(row.status));
  if(!valid) throw engineError('ENGINE_RESULT_UNVERIFIED','서버 응답을 확인할 수 없습니다. 정상으로 판단하지 말고 연결 계약을 확인하세요.');
  // 어댑터 원본의 토큰·인증서·추가 내부 필드를 브라우저로 내보내지 않는다.
  const device=row=>({id:row.id,label:row.label,status:row.status});
  const session=row=>({id:row.id,status:row.status});
  if(kind==='identity')return {user:{id:data.user.id,label:data.user.label},device:device(data.device),session:session(data.session)};
  if(kind==='apps')return data.map(row=>({id:row.id,name:row.name}));
  if(kind==='decision')return {appId:data.appId,decision:data.decision,reason:data.reason,checkedAt:data.checkedAt};
  if(kind==='events')return data.map(row=>({id:row.id,kind:row.kind,at:row.at,appId:id(row.appId)?row.appId:null,summary:row.summary,evidence:row.evidence.map(e=>({id:e.id,text:e.text})),rules:row.rules.map(r=>({id:r.id,text:r.text})),state:{access:row.state.access,session:row.state.session,device:row.state.device},supportedActions:[...row.supportedActions]}));
  if(kind==='devices')return data.map(device);
  if(kind==='sessions')return data.map(session);
  throw engineError('ENGINE_RESULT_UNVERIFIED','서버 결과 형식을 확인할 수 없습니다.');
}
// 본인 조회의 범위·생략 여부는 원 배열의 데이터 속성에서만 읽는다.
// 기존 어댑터에 이 정보가 없으면 기존 응답을 유지한다.
function collectionCoverage(kind,rows) {
  const specs={events:['own-recorded-events',40],devices:['own-registered-devices',100],sessions:['current-verified-connection',1]};
  if(!Object.hasOwn(specs,kind))return null;
  if(!Array.isArray(rows)||types.isProxy(rows))throw engineError('ENGINE_RESULT_UNVERIFIED','');
  const descriptor=Object.getOwnPropertyDescriptor(rows,'coverage');
  if(!descriptor)return null;
  if(!Object.hasOwn(descriptor,'value'))throw engineError('ENGINE_RESULT_UNVERIFIED','');
  const value=descriptor.value,keys=['schema','kind','scope','limit','total','returned','truncated','observedAtMs'];
  if(!value||typeof value!=='object'||types.isProxy(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw engineError('ENGINE_RESULT_UNVERIFIED','');
  const fields=Object.getOwnPropertyDescriptors(value);
  if(Reflect.ownKeys(fields).length!==keys.length||keys.some(key=>!Object.hasOwn(fields,key)||!Object.hasOwn(fields[key],'value')))throw engineError('ENGINE_RESULT_UNVERIFIED','');
  const c=Object.fromEntries(keys.map(key=>[key,fields[key].value])),[scope,limit]=specs[kind];
  if(c.schema!=='alekov.sdp.coverage.v1'||c.kind!==kind||c.scope!==scope||c.limit!==limit
    ||!Number.isSafeInteger(c.total)||c.total<0||!Number.isSafeInteger(c.returned)||c.returned!==rows.length||c.returned>limit||c.total<c.returned
    ||c.truncated!==(c.total>c.returned)||!Number.isSafeInteger(c.observedAtMs)||c.observedAtMs<=0
    ||c.observedAtMs>Date.now()+5000||c.observedAtMs<Date.now()-20000
    ||kind==='sessions'&&(c.total!==1||c.returned!==1))throw engineError('ENGINE_RESULT_UNVERIFIED','');
  return Object.freeze(c);
}
async function jsonBody(req,keys,validate=(key,value)=>id(value)) {
  if(!/^application\/json(?:;|$)/i.test(req.headers['content-type']??''))throw engineError('JSON_REQUIRED','JSON 요청 형식을 확인하세요.',415);
  let size=0;const chunks=[];
  for await(const chunk of req){size+=chunk.length;if(size>8192)throw engineError('REQUEST_TOO_LARGE','요청이 너무 큽니다.',413);chunks.push(chunk);}
  let body;try{body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));}catch{throw engineError('INVALID_JSON','요청 형식을 확인하세요.',400);}
  if(!record(body)||Object.keys(body).length!==keys.length||keys.some(key=>!Object.hasOwn(body,key)||!validate(key,body[key])))throw engineError('REQUEST_INVALID','요청에 필요한 항목만 보내세요.',400);
  return body;
}
// ============================================================================
// 일반 권한(unprivileged) 읽기 전용 내 PC 상태 및 보안 구성 수집기
// - 관리자 권한 상승(RunAs) 시도 없음 · 방화벽/보안 설정 변경 절대 없음
// - 읽지 못한 항목은 가짜 예시 값을 채우지 않고 status: 'unverifiable' 과 사유(reason)를 반환
// ============================================================================
let _lastCpuTimes = null;
function sumCpuTimes(cpus) {
  let idle = 0, total = 0;
  for (const core of cpus) {
    const t = core?.times || {};
    const cIdle = Number(t.idle || 0);
    const cTotal = cIdle + Number(t.user || 0) + Number(t.nice || 0) + Number(t.sys || 0) + Number(t.irq || 0);
    idle += cIdle;
    total += cTotal;
  }
  return { idle, total };
}

async function measureCpuUnprivileged() {
  try {
    const cpus1 = os.cpus();
    if (!Array.isArray(cpus1) || cpus1.length === 0) {
      return { status: 'unverifiable', reason: 'OS에서 논리 CPU 코어 목록(os.cpus)을 반환하지 않았습니다.' };
    }
    const snap1 = sumCpuTimes(cpus1);
    let prev = _lastCpuTimes;
    let method = '직전 측정 스냅샷 대비 누적 틱 차이(os.cpus)';
    if (!prev || snap1.total <= prev.total) {
      await new Promise(r => setTimeout(r, 120));
      const cpus2 = os.cpus();
      const snap2 = sumCpuTimes(cpus2);
      prev = snap1;
      _lastCpuTimes = snap2;
      method = '120ms 간격 실시간 CPU 틱 샘플링(os.cpus)';
    } else {
      _lastCpuTimes = snap1;
    }
    const cur = _lastCpuTimes;
    const totalDiff = cur.total - prev.total;
    const idleDiff = cur.idle - prev.idle;
    if (totalDiff <= 0) {
      return { status: 'unverifiable', reason: 'CPU 틱 변화량이 0이어서 사용률을 계산할 수 없습니다.' };
    }
    const usagePercent = Number((((totalDiff - idleDiff) / totalDiff) * 100).toFixed(1));
    return {
      status: 'ok',
      usagePercent: Math.max(0, Math.min(100, usagePercent)),
      unit: '%',
      cores: cpus1.length,
      model: String(cpus1[0]?.model || '').trim(),
      method,
    };
  } catch {
    return { status: 'unverifiable', reason: '일반 권한에서 CPU 사용률(os.cpus)을 읽는 중 예외가 발생했습니다.' };
  }
}

function measureMemoryUnprivileged() {
  try {
    const totalBytes = os.totalmem();
    const freeBytes = os.freemem();
    if (!Number.isFinite(totalBytes) || totalBytes <= 0 || !Number.isFinite(freeBytes) || freeBytes < 0) {
      return { status: 'unverifiable', reason: 'OS 메모리 수치(totalmem/freemem)가 유효하지 않습니다.' };
    }
    const usedBytes = Math.max(0, totalBytes - freeBytes);
    const gib = 1024 ** 3;
    return {
      status: 'ok',
      usedGiB: Number((usedBytes / gib).toFixed(2)),
      freeGiB: Number((freeBytes / gib).toFixed(2)),
      totalGiB: Number((totalBytes / gib).toFixed(2)),
      usagePercent: Number(((usedBytes / totalBytes) * 100).toFixed(1)),
      unit: 'GiB',
    };
  } catch {
    return { status: 'unverifiable', reason: '일반 권한에서 메모리 사용량(os.totalmem/freemem)을 읽지 못했습니다.' };
  }
}

async function measureDiskUnprivileged(targetPath) {
  try {
    if (typeof statfs !== 'function') {
      return { status: 'unverifiable', reason: '현재 Node.js 런타임에서 fs.statfs 함수를 지원하지 않습니다.' };
    }
    const st = await statfs(targetPath);
    const bsize = Number(st?.bsize || 0);
    const blocks = Number(st?.blocks || 0);
    const bavail = Number(st?.bavail ?? st?.bfree ?? 0);
    if (bsize <= 0 || blocks <= 0) {
      return { status: 'unverifiable', reason: '파일시스템 블록 크기(statfs)가 0 이하입니다.' };
    }
    const totalBytes = blocks * bsize;
    const freeBytes = bavail * bsize;
    const usedBytes = Math.max(0, totalBytes - freeBytes);
    const gib = 1024 ** 3;
    const driveMatch = /^[A-Za-z]:/.exec(String(targetPath));
    return {
      status: 'ok',
      mount: driveMatch ? driveMatch[0] : targetPath,
      freeGiB: Number((freeBytes / gib).toFixed(2)),
      totalGiB: Number((totalBytes / gib).toFixed(2)),
      freePercent: Number(((freeBytes / totalBytes) * 100).toFixed(1)),
      usedPercent: Number(((usedBytes / totalBytes) * 100).toFixed(1)),
      unit: 'GiB',
    };
  } catch {
    return { status: 'unverifiable', reason: '일반 권한으로 현재 작업 드라이브의 남은 공간(fs.statfs)을 읽지 못했습니다.' };
  }
}

function measureNetworkUnprivileged() {
  try {
    const raw = os.networkInterfaces();
    if (!raw || typeof raw !== 'object') {
      return { status: 'unverifiable', reason: '네트워크 인터페이스 목록(os.networkInterfaces)을 읽을 수 없습니다.' };
    }
    const interfaces = [];
    for (const [name, addrs] of Object.entries(raw)) {
      if (!Array.isArray(addrs)) continue;
      for (const addr of addrs) {
        if (!addr || addr.internal) continue;
        if (addr.family === 'IPv4' || addr.family === 4) {
          interfaces.push({
            name: String(name),
            family: 'IPv4',
            address: String(addr.address || ''),
            netmask: String(addr.netmask || ''),
          });
        }
      }
    }
    return {
      status: 'ok',
      interfaces: interfaces.slice(0, 12),
    };
  } catch {
    return { status: 'unverifiable', reason: '일반 권한으로 네트워크 구성을 읽는 중 오류가 발생했습니다.' };
  }
}

function readWindowsFirewallAndEventsUnprivileged() {
  if (process.platform !== 'win32') {
    return Promise.resolve({
      firewall: {
        status: 'unverifiable',
        reason: `현재 실행 운영체제가 Windows가 아님(${process.platform}) — Windows 방화벽 프로필 조회 대상이 아닙니다.`,
      },
      windowsEvents: {
        status: 'unverifiable',
        reason: `현재 실행 운영체제가 Windows가 아님(${process.platform}) — Windows Event Log(System·Application) 조회 대상이 아닙니다.`,
      },
    });
  }

  const psScript = `
$ErrorActionPreference = 'Stop'
$out = @{
  firewall = @{ status = 'unverifiable'; reason = '방화벽 상태를 읽지 못했습니다.' }
  windowsEvents = @{ status = 'unverifiable'; reason = 'Windows 기록을 읽지 못했습니다.' }
}
try {
  $profiles = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled
  $profList = @()
  foreach ($p in $profiles) {
    $stateStr = if ($p.Enabled -eq $true -or $p.Enabled -eq 1 -or [string]$p.Enabled -eq 'True') { '켜짐(ON)' } else { '꺼짐(OFF)' }
    $profList += @{ profile = [string]$p.Name; state = $stateStr }
  }
  $out.firewall = @{
    status = 'ok'
    profiles = $profList
    summary = '일반 권한 읽기 전용 조회 완료 (설정 변경 없음)'
  }
} catch {
  $out.firewall = @{
    status = 'unverifiable'
    reason = '일반 사용자 권한에서 방화벽 프로필(Get-NetFirewallProfile) 읽기가 거부되었거나 지원되지 않습니다(관리자 권한 요청 안 함).'
  }
}

try {
  $since = (Get-Date).AddHours(-24)
  $sysResult = @{ status = 'ok'; warningCount = 0; errorCount = 0 }
  try {
    $sysEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = @(2,3); StartTime = $since } -MaxEvents 1000 -ErrorAction Stop)
    $sysResult.errorCount = @($sysEvents | Where-Object { $_.Level -eq 2 }).Count
    $sysResult.warningCount = @($sysEvents | Where-Object { $_.Level -eq 3 }).Count
  } catch {
    if ($_.Exception.Message -match 'No events were found|이벤트가 없습니다') {
      $sysResult = @{ status = 'ok'; warningCount = 0; errorCount = 0 }
    } else {
      $sysResult = @{ status = 'unverifiable'; reason = '일반 권한으로 System 로그에 접근할 수 없습니다.' }
    }
  }

  $appResult = @{ status = 'ok'; warningCount = 0; errorCount = 0 }
  try {
    $appEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = @(2,3); StartTime = $since } -MaxEvents 1000 -ErrorAction Stop)
    $appResult.errorCount = @($appEvents | Where-Object { $_.Level -eq 2 }).Count
    $appResult.warningCount = @($appEvents | Where-Object { $_.Level -eq 3 }).Count
  } catch {
    if ($_.Exception.Message -match 'No events were found|이벤트가 없습니다') {
      $appResult = @{ status = 'ok'; warningCount = 0; errorCount = 0 }
    } else {
      $appResult = @{ status = 'unverifiable'; reason = '일반 권한으로 Application 로그에 접근할 수 없습니다.' }
    }
  }

  if ($sysResult.status -eq 'ok' -or $appResult.status -eq 'ok') {
    $total = ([int]($sysResult.warningCount) + [int]($sysResult.errorCount) + [int]($appResult.warningCount) + [int]($appResult.errorCount))
    $out.windowsEvents = @{
      status = 'ok'
      windowHours = 24
      system = $sysResult
      application = $appResult
      totalCount = $total
      note = '이 건수는 최근 24시간 일반 운영체제 경고·오류 통계이며 침해나 공격 탐지 결과가 아닙니다.'
    }
  } else {
    $out.windowsEvents = @{
      status = 'unverifiable'
      reason = '일반 사용자 권한 제한으로 System 및 Application 이벤트 로그를 읽을 수 없습니다(관리자 권한 요청 안 함).'
    }
  }
} catch {
  $out.windowsEvents = @{
    status = 'unverifiable'
    reason = '일반 사용자 권한으로 Windows 이벤트 로그를 조회하는 중 제한이 발생했습니다.'
  }
}
$out | ConvertTo-Json -Compress -Depth 5
`;

  return new Promise((resolvePromise) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', psScript],
      { timeout: 3500, windowsHide: true, maxBuffer: 256 * 1024 },
      (err, stdout) => {
        if (err || !stdout) {
          resolvePromise({
            firewall: {
              status: 'unverifiable',
              reason: '일반 권한 PowerShell 조회가 시간 초과되었거나 거부되었습니다(관리자 권한으로 전환하지 않음).',
            },
            windowsEvents: {
              status: 'unverifiable',
              reason: '일반 권한 PowerShell 이벤트 로그 조회가 시간 초과되었거나 거부되었습니다(관리자 권한으로 전환하지 않음).',
            },
          });
          return;
        }
        try {
          const parsed = JSON.parse(String(stdout).trim());
          resolvePromise({
            firewall: parsed?.firewall || { status: 'unverifiable', reason: '방화벽 응답 형식 확인 불가' },
            windowsEvents: parsed?.windowsEvents || { status: 'unverifiable', reason: '이벤트 로그 응답 형식 확인 불가' },
          });
        } catch {
          resolvePromise({
            firewall: { status: 'unverifiable', reason: '방화벽 조회 출력 JSON을 해석할 수 없습니다.' },
            windowsEvents: { status: 'unverifiable', reason: 'Windows 기록 출력 JSON을 해석할 수 없습니다.' },
          });
        }
      }
    );
  });
}

async function collectLocalPcTelemetry(targetDir, nowIso) {
  const [cpu, disk, winSec] = await Promise.all([
    measureCpuUnprivileged(),
    measureDiskUnprivileged(targetDir),
    readWindowsFirewallAndEventsUnprivileged(),
  ]);
  const memory = measureMemoryUnprivileged();
  const network = measureNetworkUnprivileged();
  return {
    measuredAt: nowIso,
    privilegeLevel: 'standard-user-unprivileged-readonly',
    intrusionDisclaimer: '이 측정값과 Windows 기록 건수는 침해나 공격 탐지 결과가 아닙니다.',
    cpu,
    memory,
    disk,
    network,
    firewall: winSec.firewall,
    windowsEvents: winSec.windowsEvents,
  };
}

export function createOnServer(serverOptions={}) {
  if(!serverOptions||typeof serverOptions!=='object'||types.isProxy(serverOptions))throw Error('INVALID_SERVER_AI_CONFIGURATION');
  const sdpDescriptor=Object.getOwnPropertyDescriptor(serverOptions,'sdpHostEngine');let sdpHostEngine=null;
  if(sdpDescriptor){
    if(!Object.hasOwn(sdpDescriptor,'value')||!sdpDescriptor.enumerable||sdpDescriptor.value!==undefined&&!isOwnedSdpHostEngine(sdpDescriptor.value))throw Error('INVALID_SERVER_AI_CONFIGURATION');
    sdpHostEngine=sdpDescriptor.value??null;
  }else for(let p=Object.getPrototypeOf(serverOptions);p;p=Object.getPrototypeOf(p)){if(types.isProxy(p)||Object.getOwnPropertyDescriptor(p,'sdpHostEngine'))throw Error('INVALID_SERVER_AI_CONFIGURATION');}
  const nativeDescriptor=Object.getOwnPropertyDescriptor(serverOptions,'nativeHostConfiguration');let nativeConfiguration=null;
  if(nativeDescriptor){if(!Object.hasOwn(nativeDescriptor,'value')||!nativeDescriptor.enumerable)throw Error('INVALID_SERVER_AI_CONFIGURATION');
    nativeConfiguration=captureNativeHostConfiguration(nativeDescriptor.value);}
  else for(let p=Object.getPrototypeOf(serverOptions);p;p=Object.getPrototypeOf(p)){if(types.isProxy(p)||Object.getOwnPropertyDescriptor(p,'nativeHostConfiguration'))throw Error('INVALID_SERVER_AI_CONFIGURATION');}
  const {engine={evidenceMode:'disconnected'},actionConfiguration:givenActionConfiguration,sdpActionStartup,ai,resolveAiIdentity,readLearnerSupportIdentity,aiEnv=process.env,appCredentialVault,vaultAiConfiguration,aiConnectionConfiguration,allowLoopbackAiHttp=false,aiTimeoutMs=10000,
    scanner=createProjectScanner(),assetsRoot=root,clock=()=>new Date(),readTimeoutMs=10000,requestTimeoutMs=15000}=serverOptions;
  if(nativeConfiguration&&(ai!==undefined||resolveAiIdentity!==undefined||readLearnerSupportIdentity!==undefined||appCredentialVault!==undefined||vaultAiConfiguration!==undefined||aiConnectionConfiguration!==undefined||typeof aiEnv.ON_AI_APP_KEY==='string'&&aiEnv.ON_AI_APP_KEY))throw Error('INVALID_SERVER_AI_CONFIGURATION');
  const nativeHost=nativeConfiguration?createNativeHostContext(nativeConfiguration):null;
  // c2(#978): host 가 sdpActionStartup({databasePath, policy})을 주면, 이 서버가 만든 SDP host engine 과 genuine native host 를
  // createSdpActionConfiguration 에 그대로 넘긴다(자기 철회 뒤 본인 영수증 포함). identityVersion 은 같은 native host operation 에서 읽는다.
  // 학생 body·header 로 DB·정책·engine·nativeHost 를 고를 수 없다. actionConfiguration 과 함께 주거나 SDP·native host 가 없으면 거절한다.
  let actionConfiguration=givenActionConfiguration;
  if(sdpActionStartup!==undefined){
    // C4: 이 분기에서 거절되면 방금 만든 nativeHost 를 닫고 실패한다(서버 객체가 없어 close 이벤트로 정리되지 않는다).
    try{
      if(givenActionConfiguration!==undefined||!sdpHostEngine||!nativeHost||!record(sdpActionStartup)||Object.keys(sdpActionStartup).some(key=>!['databasePath','policy'].includes(key)))throw Error('INVALID_SERVER_ACTION_CONFIGURATION');
      const readIdentityVersion=async({signal}={})=>{
        const cap=await openNativeHostOperation(nativeHost,{signal,timeoutMs:10000});
        try{return (await readNativeHostOperation(nativeHost,cap)).identityVersion;}finally{closeNativeHostOperation(cap);}
      };
      actionConfiguration=createSdpActionConfiguration({sdpHost:sdpHostEngine,nativeHost,readIdentityVersion,databasePath:sdpActionStartup.databasePath,policy:sdpActionStartup.policy});
    }catch(error){nativeHost?.close();throw error;}
  }
  if(!Number.isSafeInteger(requestTimeoutMs)||requestTimeoutMs<=0||requestTimeoutMs>120000||resolveAiIdentity!==undefined&&typeof resolveAiIdentity!=='function'
    ||readLearnerSupportIdentity!==undefined&&(typeof readLearnerSupportIdentity!=='function'||types.isProxy(readLearnerSupportIdentity))
    ||appCredentialVault!==undefined&&(typeof appCredentialVault?.load!=='function'||ai!==undefined||typeof aiEnv.ON_AI_APP_KEY==='string'&&aiEnv.ON_AI_APP_KEY.length>0))throw Error('INVALID_SERVER_AI_CONFIGURATION');
  const defaultAi=ai??(appCredentialVault?createVaultOnAiService({appAuthorization:{},...vaultAiConfiguration,enabled:true,vault:appCredentialVault,timeoutMs:aiTimeoutMs}):createOnAiService({env:aiEnv,allowLoopbackHttp:allowLoopbackAiHttp,timeoutMs:aiTimeoutMs}));
  let mappedAi=appCredentialVault?defaultAi:ai;
  const aiSecrets=!appCredentialVault&&typeof aiEnv.ON_AI_APP_KEY==='string'?[aiEnv.ON_AI_APP_KEY]:[];
  const mappedService=()=>mappedAi??(mappedAi=createOnAiService({env:aiEnv,allowLoopbackHttp:allowLoopbackAiHttp,timeoutMs:aiTimeoutMs,appAuthorization:{}}));
  const mode=['connected','demo','disconnected'].includes(engine.evidenceMode)?engine.evidenceMode:'disconnected';
  const connectionConfigKeys=['enabled','fetchImpl','clock','startTimeoutMs','scopeTimeoutMs','finishTimeoutMs','pollIntervalMs','maxFlows','retainMs'];
  if(!Number.isSafeInteger(readTimeoutMs)||readTimeoutMs<=0||readTimeoutMs>120000
    || aiConnectionConfiguration!==undefined&&(!record(aiConnectionConfiguration)||Object.keys(aiConnectionConfiguration).some(key=>!connectionConfigKeys.includes(key))
      || typeof aiConnectionConfiguration.enabled!=='boolean'
      || aiConnectionConfiguration.enabled&&(mode!=='connected'||typeof appCredentialVault?.load!=='function'||typeof appCredentialVault?.persistCredential!=='function'
        || !resolveAiIdentity&&typeof engine.readAiIdentity!=='function')))throw Error('INVALID_SERVER_CONNECTION_CONFIGURATION');
  // Shared identity/binding logic, parameterized by an operation's own readers.
  // The manager never retains the lifetime or reader of an HTTP request.
  function sourceReader({call,bounded,assertAlive}) {
    async function captureSource(){
      const identity=assertData('identity',await call('readIdentity'));
      const source=Object.freeze({sourceSubjectId:identity.user.id,projectId:engine.projectId,sessionId:identity.session.id});
      if(!id(source.projectId)||identity.session.status!=='active')throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
      return {identity,source};
    }
    async function assertCurrent(source){
      const identity=assertData('identity',await call('readIdentity'));
      if(identity.user.id!==source.sourceSubjectId||identity.session.id!==source.sessionId||identity.session.status!=='active'||engine.projectId!==source.projectId)
        throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
    }
    async function readMapping(source){
      if(!resolveAiIdentity&&typeof engine.readAiIdentity!=='function')throw engineError('ON_AI_PROVISIONING_PENDING','');
      let raw;
      try {raw=resolveAiIdentity?await bounded(signal=>resolveAiIdentity(source,{signal})):await call('readAiIdentity',source);}
      catch(error){if(['REQUEST_TIMEOUT','REQUEST_CANCELLED','ENGINE_TIMEOUT'].includes(error?.code))throw error;throw engineError('ON_AI_PROVISIONING_PENDING','');}
      let snapshot;try{snapshot=structuredClone(raw);}catch{throw engineError('ON_AI_PROVISIONING_PENDING','');}
      await assertCurrent(source);
      return assertAiBinding(snapshot,source);
    }
    async function finishMapping(source,binding){
      let after;
      try{after=await readMapping(source);}catch(error){if(error?.code==='ON_AI_PROVISIONING_PENDING')throw engineError('SUBJECT_SCOPE_UNVERIFIED','');throw error;}
      if(AI_BINDING_KEYS.some(key=>after[key]!==binding[key]))throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
      assertAlive();
    }
    return {captureSource,assertCurrent,readMapping,finishMapping};
  }
  const connectionReads=new Set();
  async function readConnectionScope() {
    const controller=new AbortController();connectionReads.add(controller);
    let timer,stop;
    const assertAlive=()=>{if(controller.signal.aborted)throw engineError('ENGINE_TIMEOUT','');};
    const stopped=new Promise((_,reject)=>{
      stop=()=>reject(engineError('ENGINE_TIMEOUT',''));
      controller.signal.addEventListener('abort',stop,{once:true});
      timer=setTimeout(()=>controller.abort(),readTimeoutMs);
    });
    const bounded=async work=>{
      assertAlive();const value=await Promise.race([Promise.resolve().then(()=>{assertAlive();return work(controller.signal);}),stopped]);assertAlive();return value;
    };
    const call=(name,...args)=>bounded(signal=>engineMethod(engine,name)(...args,{signal}));
    try {
      const reader=sourceReader({call,bounded,assertAlive});
      const {source}=await reader.captureSource(),binding=await reader.readMapping(source);
      await reader.finishMapping(source,binding);assertAlive();return binding;
    } finally {clearTimeout(timer);controller.signal.removeEventListener('abort',stop);controller.abort();connectionReads.delete(controller);}
  }
  const connections=nativeHost?createConnectionManager({enabled:true,nativeHost,...(nativeConfiguration.fetchImpl?{fetchImpl:nativeConfiguration.fetchImpl}:{}),...(nativeConfiguration.clock?{clock:nativeConfiguration.clock}: {})}):createConnectionManager(aiConnectionConfiguration?.enabled===true
    ? {...aiConnectionConfiguration,readServerScope:readConnectionScope,vault:appCredentialVault}:{});
  if(aiConnectionConfiguration?.enabled===true&&!connections.available)throw Error('INVALID_SERVER_CONNECTION_CONFIGURATION');
  // Only the local server owner can supply this configuration. The browser
  // cannot choose a DB, policy, engine, resolver, actor or command body.
  const actionRequests=new AsyncLocalStorage();
  const actionContextKeys=['subjectId','projectId','sessionId','identityVersion','appId','audience','accessPolicyId','engineGeneration','sourcePolicyVersion'];
  // C2-R2b: host 가 조치 전용 engine 을 주면 그것만 쓴다(학생 모듈 engine 은 조치에 쓰지 않음). 없으면 기존 동작 그대로.
  const actionEngine=actionConfiguration&&Object.hasOwn(actionConfiguration,'engine')?actionConfiguration.engine:engine;
  const actions=createActionService({engine:actionEngine,databasePath:actionConfiguration?.databasePath,policy:actionConfiguration?.policy,clock:actionConfiguration?.clock,
    resolveContext:typeof actionConfiguration?.resolveContext==='function'?async({signal})=>{
      const request=actionRequests.getStore();if(!request)throw Error('ACTION_SCOPE_UNVERIFIED');
      await request.assertCurrent(request.source);
      const raw=await actionConfiguration.resolveContext({signal});
      const snapshot=structuredClone(raw);
      await request.assertCurrent(request.source);
      if(snapshot?.subjectId!==request.source.sourceSubjectId||snapshot?.projectId!==request.source.projectId||snapshot?.sessionId!==request.source.sessionId)
        throw Object.assign(Error('ACTION_SCOPE_CHANGED'),{code:'ACTION_SCOPE_CHANGED'});
      if(!request.actionContext)request.actionContext=Object.freeze(structuredClone(snapshot));
      return snapshot;
    }:undefined});
  const meta=()=>({mode,checkedAt:clock().toISOString(),starterVersion:'0.1.0'});
  const server=http.createServer(async(req,res)=>{
    // Register before identity/events reads: disconnects during preparation must
    // cancel the later AI operation, even when an adapter ignores cancellation.
    const lifetime=new AbortController();
    const requestStartedAt={wall:Date.now(),monotonic:performance.now()};
    let requestTimedOut=false;
    let nativeAiCheck=false;
    let supportTimer;
    let supportDeadline;
    const disconnect=()=>lifetime.abort();
    res.once('close',disconnect);req.once('aborted',disconnect);
    const requestTimer=setTimeout(()=>{requestTimedOut=true;lifetime.abort();},requestTimeoutMs);
    function assertAlive(){if(supportDeadline&&(Date.now()>=supportDeadline.wall||performance.now()>=supportDeadline.monotonic)){requestTimedOut=true;lifetime.abort();}if(requestTimedOut)throw engineError('REQUEST_TIMEOUT','');if(lifetime.signal.aborted||res.destroyed)throw engineError('REQUEST_CANCELLED','');}
    async function bounded(work){
      assertAlive();let cancel;
      const stopped=new Promise((_,reject)=>{
        cancel=()=>reject(engineError(requestTimedOut?'REQUEST_TIMEOUT':'REQUEST_CANCELLED',''));
        lifetime.signal.addEventListener('abort',cancel,{once:true});
      });
      try {const value=await Promise.race([Promise.resolve().then(()=>{assertAlive();return work(lifetime.signal);}),stopped]);assertAlive();return value;}
      finally {lifetime.signal.removeEventListener('abort',cancel);}
    }
    async function call(name,...args){
      assertAlive();
      let timer,cancel;const controller=new AbortController();
      const stopped=new Promise((_,reject)=>{
        cancel=()=>{controller.abort();reject(engineError(requestTimedOut?'REQUEST_TIMEOUT':'REQUEST_CANCELLED',''));};
        lifetime.signal.addEventListener('abort',cancel,{once:true});
        timer=setTimeout(()=>{controller.abort();reject(engineError('ENGINE_TIMEOUT',''));},readTimeoutMs);
      });
      try{const value=await Promise.race([engineMethod(engine,name)(...args,{signal:controller.signal}),stopped]);assertAlive();return value;}
      finally{clearTimeout(timer);lifetime.signal.removeEventListener('abort',cancel);controller.abort();}
    }
    const requestId=randomUUID();
    let actionRequest=false;
    const send=(status,body)=>{if(res.destroyed||res.writableEnded)return;res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','x-on-request-id':requestId});res.end(JSON.stringify({...body,meta:meta()}));};
    const {captureSource,assertCurrent,readMapping,finishMapping}=sourceReader({call,bounded,assertAlive});
    const authOptions=(binding)=>({expectedScope:Object.freeze({subjectId:binding.canonicalStudentId,projectId:binding.projectId,appId:'aleph-on',audience:'on-client'}),
      expectedContext:Object.freeze({alephUserId:binding.alephUserId,siteId:binding.siteId,identityVersion:binding.identityVersion}),signal:lifetime.signal});
    try{
      const address=server.address();const port=typeof address==='object'?address.port:0;
      const allowedHosts=[`127.0.0.1:${port}`,`localhost:${port}`];
      const host=req.headers.host;
      if(!allowedHosts.includes(host))throw engineError('HOST_REJECTED','로컬 실행 주소를 확인하세요.',403);
      const url=new URL(req.url,`http://${host}`);
      if(url.search)throw engineError('QUERY_REJECTED','지원하지 않는 요청입니다.',400);
      if(url.pathname.startsWith('/api/')&&req.headers['sec-fetch-site']==='cross-site')throw engineError('ORIGIN_REJECTED','');
      if(req.method==='POST'&&req.headers.origin!==`http://${host}`)throw engineError('ORIGIN_REJECTED','앱 화면에서 다시 요청하세요.',403);
      if(url.pathname.startsWith('/api/native-login/')){
        const kind=url.pathname.slice('/api/native-login/'.length);
        if(req.method!=='POST'||!['start','status','redeem','current','cancel'].includes(kind)){send(404,{ok:false,error:{code:'NOT_FOUND',message:'지원하지 않는 주소입니다.',retryable:false}});return;}
        if(!nativeHost){send(503,{ok:false,error:{code:'NATIVE_HOST_DISABLED',message:'호스트 로그인 연결을 먼저 준비하세요.',retryable:false}});return;}
        if(req.headers.authorization!==undefined||['x-clco-mode','x-clco-work-mode','x-clco-eval-run-id','x-clco-eval-run-nonce','x-clco-capacity-run'].some(name=>req.headers[name]!==undefined))throw engineError('REQUEST_INVALID','');
        if(Number(req.headers['content-length']??0)>8192)throw engineError('REQUEST_TOO_LARGE','',413);
        await bounded(()=>jsonBody(req,[]));
        try{const data=await bounded(signal=>nativeHost.login[kind]({}, {signal}));assertAlive();send(200,{ok:true,data});}
        catch(error){const code=nativePublicError(error);send(code==='NATIVE_HOST_INPUT_INVALID'?400:code==='NATIVE_HOST_EXPIRED'?410:409,{ok:false,error:{code,message:'현재 로그인 연결을 확인하세요. 자동으로 재시도하지 않습니다.',retryable:false}});}
        return;
      }
      if(req.method==='GET'&&files.has(url.pathname)){
        const data=await readFile(resolve(assetsRoot,files.get(url.pathname)));
        const type=url.pathname.endsWith('.webp')?'image/webp':url.pathname.endsWith('.css')?'text/css':url.pathname.endsWith('.js')||url.pathname.endsWith('.mjs')?'text/javascript':'text/html';
        res.writeHead(200,{'content-type':type==='image/webp'?type:`${type}; charset=utf-8`,'cache-control':'no-store','content-security-policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",'x-content-type-options':'nosniff'});res.end(data);return;
      }
      if(req.method==='POST'&&connectionRoutes.has(url.pathname)){
        const kind=connectionRoutes.get(url.pathname),keys=kind==='start'?[]:['connectionId'];
        // Reject a declared oversized body before the stream iterator can abort
        // the request and turn the intended 413 into a disconnect result.
        if(/^\d+$/.test(req.headers['content-length']??'')&&Number(req.headers['content-length'])>8192)throw engineError('REQUEST_TOO_LARGE','');
        const input=await bounded(()=>jsonBody(req,keys,(_key,value)=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)));
        const output=await bounded(signal=>connections[kind](input,{signal}));
        send(output.status,output.body);return;
      }
      const gets=new Map([['/api/me',['readIdentity','identity']],['/api/apps',['readApps','apps']],['/api/events',['readEvents','events']],['/api/devices',['readDevices','devices']],['/api/sessions',['readSessions','sessions']]]);
      if(req.method==='GET'&&gets.has(url.pathname)){
        const [name,kind]=gets.get(url.pathname);
        let raw;
        if(mode==='connected'&&kind!=='identity'){
          const identity=assertData('identity',await call('readIdentity'));
          const scope=Object.freeze({subjectId:identity.user.id,projectId:engine.projectId,appId:'aleph-on',audience:'on-client'});
          if(!id(scope.projectId)||identity.session.status!=='active')throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
          raw=await call(name,scope);
          if(!Array.isArray(raw)||raw.some(row=>row.subjectId!==scope.subjectId||row.projectId!==scope.projectId))throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
          const after=assertData('identity',await call('readIdentity'));
          if(after.user.id!==identity.user.id||after.session.id!==identity.session.id||after.session.status!=='active'||engine.projectId!==scope.projectId)throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
        }else raw=await call(name);
        const data=assertData(kind,raw),coverage=collectionCoverage(kind,raw);send(200,{ok:true,data,...(coverage?{coverage}:{})});return;
      }
      if(req.method==='POST'&&url.pathname==='/api/access'){
        const input=await bounded(()=>jsonBody(req,['appId']));let raw;
        if(mode==='connected'){
          const identity=assertData('identity',await call('readIdentity'));
          const scope=Object.freeze({subjectId:identity.user.id,projectId:engine.projectId,appId:'aleph-on',audience:'on-client'});
          if(!id(scope.projectId)||identity.session.status!=='active')throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
          raw=await call('decideAccess',Object.freeze({...input,requestId}),scope);
          if(!record(raw)||raw.subjectId!==scope.subjectId||raw.projectId!==scope.projectId||raw.requestId!==requestId)throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
          const after=assertData('identity',await call('readIdentity'));
          if(after.user.id!==identity.user.id||after.session.id!==identity.session.id||after.session.status!=='active'||engine.projectId!==scope.projectId)throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
        }else raw=await call('decideAccess',input);
        const data=assertData('decision',raw);
        if(data.appId!==input.appId)throw engineError('ENGINE_RESULT_UNVERIFIED','접속 판정 대상이 요청한 업무 앱과 일치하지 않습니다.');
        send(200,{ok:true,data});return;
      }
      const actionRoutes=new Map([['/api/actions/prepare',['prepare',['eventId','actionId']]],['/api/actions/execute',['execute',['requestId','confirmationId']]],['/api/actions/result',['readResult',['requestId']]]]);
      if(req.method==='POST'&&actionRoutes.has(url.pathname)){
        actionRequest=true;
        const [method,keys]=actionRoutes.get(url.pathname);
        const input=await bounded(()=>jsonBody(req,keys,(key,value)=>key==='confirmationId'?confirmation(value):key==='requestId'?uuid(value):id(value)));
        // A confirmation ticket supplies no authority. Capture the current
        // source identity even for a replay; service also rechecks all generations.
        if(!actionConfiguration){const projected=projectAction({ok:false,error:{code:'ACTION_UNSUPPORTED'}},method,input);send(projected.status,projected.body);return;}
        let source;
        try{({source}=await captureSource());}
        catch(error){
          // c2(#978): 이 기기를 스스로 철회한 뒤에는 현재 SDP identity 를 읽을 수 없다. 결과 조회이고 엔진이 본인 영수증 경로를 줄 때만
          // 현재 context 없이 서비스로 넘긴다. 서비스는 소비된 device:revoke 행만 본인 영수증(철회 기기 인증서·native canonical4·host project)으로 읽고,
          // 그 밖의 행·조치는 기존 오류 그대로다. 현재 context 가 없으므로 마지막 9필드 재대조는 하지 않는다(현재 권한을 주장하지 않는 영수증).
          // 철회된 기기의 relay 거절이 어떤 코드로 오는지(SUBJECT_SCOPE_UNVERIFIED·ENGINE_NOT_CONNECTED 등)는 relay 경로마다 다르므로 코드로 고르지 않고,
          // 취소·시간 초과만 제외한다. 권한은 아래 본인 영수증 경로가 스스로 증명해야 하며 여기서 넓어지지 않는다.
          if(method!=='readResult'||typeof actionEngine?.readOwnRevokedReceipt!=='function'||lifetime.signal.aborted
            ||['REQUEST_TIMEOUT','REQUEST_CANCELLED','ENGINE_TIMEOUT'].includes(error?.code))throw error;
          const ownScope={source:null,assertCurrent:async()=>{throw Object.assign(Error('ACTION_SCOPE_UNVERIFIED'),{code:'ACTION_SCOPE_UNVERIFIED'});},actionContext:null};
          let ownRaw;
          try{ownRaw=await actionRequests.run(ownScope,()=>bounded(signal=>actions.readResult(input,{signal})));}
          catch(failure){if(failure?.code==='REQUEST_TIMEOUT'){const projected=projectAction({ok:false,error:{code:'ACTION_TIMEOUT'}},method,input);send(projected.status,projected.body);return;}throw failure;}
          assertAlive();
          const projected=projectAction(structuredClone(ownRaw),'result',input);send(projected.status,projected.body);return;
        }
        let raw;
        const actionRequestScope={source,assertCurrent,actionContext:null};
        try{raw=await actionRequests.run(actionRequestScope,()=>bounded(signal=>actions[method](input,{signal})));}
        catch(error){
          if(error?.code==='REQUEST_TIMEOUT'){
            const projected=projectAction({ok:false,error:{code:'ACTION_TIMEOUT'}},method,input);send(projected.status,projected.body);return;
          }
          throw error;
        }
        const snapshot=structuredClone(raw);
        await assertCurrent(source);assertAlive();
        // The last identity read can yield after the module has committed. Bind
        // the public receipt to the full current authority, not just stable IDs.
        if(snapshot?.ok===true){
          const current=await bounded(async signal=>structuredClone(await actionConfiguration.resolveContext({signal})));
          const captured=actionRequestScope.actionContext;
          if(!captured||!exact(current,actionContextKeys)||actionContextKeys.some(key=>current[key]!==captured[key])){
            const projected=projectAction({ok:false,error:{code:'ACTION_SCOPE_CHANGED'}},method,input);
            send(projected.status,projected.body);return;
          }
        }
        const projected=projectAction(snapshot,method==='readResult'?'result':method,input);
        send(projected.status,projected.body);return;
      }
      if(req.method==='POST'&&url.pathname==='/api/ai/explain'&&nativeHost){
        if(!Number.isSafeInteger(aiTimeoutMs)||aiTimeoutMs<=0||aiTimeoutMs>120000){
          send(503,{ok:false,error:{code:'WB_CLCO_INVALID_LIMIT',message:aiErrorMessages.WB_CLCO_INVALID_LIMIT,retryable:false}});return;
        }
        const routeLimit=Math.min(aiTimeoutMs,requestTimeoutMs);
        supportDeadline={wall:requestStartedAt.wall+routeLimit,monotonic:requestStartedAt.monotonic+routeLimit};
        const remaining=()=>{assertAlive();return Math.max(1,Math.floor(Math.min(supportDeadline.wall-Date.now(),supportDeadline.monotonic-performance.now())));};
        supportTimer=setTimeout(()=>{requestTimedOut=true;lifetime.abort();},remaining());
        let nativeOperation=null,sourceOperation=null;
        const sourceCall=async work=>{try{return await bounded(work);}catch(error){assertAlive();if(['REQUEST_TIMEOUT','REQUEST_CANCELLED'].includes(error?.code))throw error;throw engineError('ON_AI_PROVISIONING_PENDING','');}};
        try{
          if(Number(req.headers['content-length']??0)>8192)throw engineError('REQUEST_TOO_LARGE','',413);
          const input=await bounded(()=>jsonBody(req,['eventId']));
          if(!isOwnedSdpHostEngine(sdpHostEngine))throw engineError('ON_AI_PROVISIONING_PENDING','');
          nativeOperation=await sourceCall(signal=>openNativeHostOperation(nativeHost,{signal,timeoutMs:remaining()}));
          const readHost=async signal=>{if(signal.aborted)throw engineError('REQUEST_CANCELLED','');const current=await sourceCall(()=>readNativeHostOperation(nativeHost,nativeOperation));assertAlive();if(signal.aborted)throw engineError('REQUEST_CANCELLED','');return current;};
          const identity=await readHost(lifetime.signal);
          sourceOperation=await sourceCall(signal=>openSdpIncidentOperation(sdpHostEngine,input,{signal,timeoutMs:remaining()}));
          const initial=assertSdpIncidentOperation(sdpHostEngine,sourceOperation),event=initial.event;
          const sameIdentity=source=>{if(Object.keys(identity).some(key=>source.binding.ai[key]!==identity[key]))throw engineError('ON_AI_PROVISIONING_PENDING','');};
          sameIdentity(initial);
          const recheck=async({signal})=>{
            if(signal.aborted)throw engineError('REQUEST_CANCELLED','');
            const current=await sourceCall(()=>readSdpIncidentOperation(sdpHostEngine,sourceOperation,{signal}));
            const native=await readHost(signal);
            if(Object.keys(identity).some(key=>native[key]!==identity[key])||current.eventHash!==initial.eventHash)throw engineError('ON_AI_PROVISIONING_PENDING','');
            sameIdentity(current);assertAlive();
            try{assertSdpIncidentOperation(sdpHostEngine,sourceOperation);assertNativeHostOperation(nativeHost,nativeOperation);}catch{throw engineError('ON_AI_PROVISIONING_PENDING','');}
            if(current.validUntilMs<=Date.now())throw engineError('ON_AI_PROVISIONING_PENDING','');
            if(signal.aborted)throw engineError('REQUEST_CANCELLED','');assertAlive();
          };
          const service=createVaultOnAiService({enabled:true,vault:createNativeOperationVault(nativeHost,nativeOperation),timeoutMs:remaining(),
            appAuthorization:nativeConfiguration.fetchImpl?{fetchImpl:nativeConfiguration.fetchImpl}:{}});
          const options=Object.freeze({signal:lifetime.signal,
            expectedScope:Object.freeze({subjectId:identity.subjectId,projectId:identity.projectId,appId:'aleph-on',audience:'on-client'}),
            expectedContext:Object.freeze({alephUserId:identity.alephUserId,siteId:identity.siteId,identityVersion:identity.identityVersion}),
            beforeDispatch:recheck,beforePublish:recheck});
          const incident={incidentId:event.id,evidence:event.evidence.map(row=>({id:row.id,summary:row.text})),rules:event.rules.map(row=>({id:row.id,description:row.text})),currentState:event.state,supportedActions:event.supportedActions};
          const raw=await bounded(()=>service.explainIncident(incident,options));
          const capture=(value,keys)=>{
            if(value===null||typeof value!=='object'||types.isProxy(value)||Object.getPrototypeOf(value)!==Object.prototype)throw engineError('SERVICE_UNAVAILABLE','');
            const descriptors=Object.getOwnPropertyDescriptors(value);
            if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(key=>!Object.hasOwn(descriptors,key)||!Object.hasOwn(descriptors[key],'value')))throw engineError('SERVICE_UNAVAILABLE','');
            return Object.fromEntries(keys.map(key=>[key,descriptors[key].value]));
          };
          if(raw===null||typeof raw!=='object'||types.isProxy(raw))throw engineError('SERVICE_UNAVAILABLE','');
          const ok=Object.getOwnPropertyDescriptor(raw,'ok');if(!ok||!Object.hasOwn(ok,'value')||typeof ok.value!=='boolean')throw engineError('SERVICE_UNAVAILABLE','');
          if(ok.value===false){const output=capture(raw,['ok','error','help']),error=capture(output.error,['code','message']);
            const code=Object.hasOwn(aiErrorMessages,error.code)?error.code:'WB_CLCO_REQUEST_FAILED';assertAlive();send(503,{ok:false,error:{code,message:aiErrorMessages[code],retryable:true}});return;}
          const output=capture(raw,['ok','transportChecked','audienceAuthorization','explanation','authorizationValidUntilMs','help']);
          if(output.transportChecked!==true||output.audienceAuthorization!=='verified'||!Number.isSafeInteger(output.authorizationValidUntilMs)||output.authorizationValidUntilMs<=Date.now())throw engineError('ON_AI_PROVISIONING_PENDING','');
          aiHelp({audienceAuthorization:'verified',help:capture(output.help,['component','code','appCredentialsConfigured','provisioning','automaticRetries','workbenchRequiredAtRuntime'])});
          const explanation=assertExplanation(capture(output.explanation,['summary','evidenceIds','proposals','requiresHumanConfirmation','executed']),event,[]);
          const body=JSON.stringify({ok:true,data:{explanation},meta:meta()});
          assertAlive();let current;
          try{current=assertSdpIncidentOperation(sdpHostEngine,sourceOperation);assertNativeHostOperation(nativeHost,nativeOperation);}catch{throw engineError('ON_AI_PROVISIONING_PENDING','');}
          sameIdentity(current);
          if(current.eventHash!==initial.eventHash||current.validUntilMs<=Date.now()||output.authorizationValidUntilMs<=Date.now())throw engineError('ON_AI_PROVISIONING_PENDING','');
          assertAlive();res.writeHead(200,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','x-on-request-id':requestId});res.end(body);return;
        }finally{closeSdpIncidentOperation(sourceOperation);closeNativeHostOperation(nativeOperation);}
      }
      if(req.method==='POST'&&url.pathname==='/api/ai/explain'){
        const {eventId}=await bounded(()=>jsonBody(req,['eventId']));
        const identity=assertData('identity',await call('readIdentity'));
        const expectedScope=Object.freeze({subjectId:identity.user.id,projectId:engine.projectId,appId:'aleph-on',audience:'on-client'});
        if(mode==='connected'&&(!id(expectedScope.projectId)||identity.session.status!=='active'))throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
        const rawEvents=await call('readEvents',expectedScope);
        if(mode==='connected'&&(!Array.isArray(rawEvents)||rawEvents.some(event=>event.subjectId!==expectedScope.subjectId||event.projectId!==expectedScope.projectId)))throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
        const events=assertData('events',rawEvents);const event=events.find(row=>row.id===eventId);
        if(!event)throw engineError('EVENT_NOT_FOUND','본인 기록에서 사건을 찾을 수 없습니다.',404);
        const after=assertData('identity',await call('readIdentity'));
        if(after.user.id!==identity.user.id||after.session.id!==identity.session.id||after.session.status!=='active'||engine.projectId!==expectedScope.projectId)throw engineError('SUBJECT_SCOPE_UNVERIFIED','');
        if(lifetime.signal.aborted||res.destroyed)throw engineError('REQUEST_CANCELLED','');
        const source=Object.freeze({sourceSubjectId:identity.user.id,projectId:expectedScope.projectId,sessionId:identity.session.id});
        const binding=await readMapping(source);
        const output=await bounded(()=>mappedService().explainIncident({incidentId:event.id,evidence:event.evidence.map(e=>({id:e.id,summary:e.text})),rules:event.rules.map(r=>({id:r.id,description:r.text})),currentState:event.state,supportedActions:event.supportedActions},authOptions(binding)));
        await finishMapping(source,binding);
        if(!output?.ok){send(503,{ok:false,error:aiFailure(output)});return;}
        send(200,{ok:true,data:{explanation:assertExplanation(output.explanation,event,aiSecrets)}});return;
      }
      if(req.method==='POST'&&url.pathname==='/api/ai/check'&&nativeHost){
        nativeAiCheck=true; // 이 요청의 바깥 catch 도 같은 retryable 정책을 쓴다(서버가 정한 표시, 요청마다 새로 만든다).
        if(!Number.isSafeInteger(aiTimeoutMs)||aiTimeoutMs<=0||aiTimeoutMs>120000){
          send(503,{ok:false,error:{code:'WB_CLCO_INVALID_LIMIT',message:aiErrorMessages.WB_CLCO_INVALID_LIMIT,retryable:false}});return;
        }
        // One deadline covers the body, original native operation, vault, models and every recheck.
        const routeLimit=Math.min(aiTimeoutMs,requestTimeoutMs);
        supportDeadline={wall:requestStartedAt.wall+routeLimit,monotonic:requestStartedAt.monotonic+routeLimit};
        const remaining=()=>{assertAlive();return Math.max(1,Math.floor(Math.min(supportDeadline.wall-Date.now(),supportDeadline.monotonic-performance.now())));};
        supportTimer=setTimeout(()=>{requestTimedOut=true;lifetime.abort();},remaining());
        let nativeOperation=null;
        try{
          if(Number(req.headers['content-length']??0)>8192)throw engineError('REQUEST_TOO_LARGE','',413);
          await bounded(()=>jsonBody(req,[]));
          try{nativeOperation=await bounded(signal=>openNativeHostOperation(nativeHost,{signal,timeoutMs:remaining()}));}
          catch(error){assertAlive();if(['REQUEST_TIMEOUT','REQUEST_CANCELLED'].includes(error?.code))throw error;throw engineError('ON_AI_PROVISIONING_PENDING','');}
          const readHost=async(signal=lifetime.signal)=>{
            assertAlive();if(signal.aborted)throw engineError('REQUEST_CANCELLED','');
            try{const value=await bounded(()=>readNativeHostOperation(nativeHost,nativeOperation));assertAlive();if(signal.aborted)throw engineError('REQUEST_CANCELLED','');return value;}
            catch(error){assertAlive();if(['REQUEST_TIMEOUT','REQUEST_CANCELLED'].includes(error?.code))throw error;throw engineError('ON_AI_PROVISIONING_PENDING','');}
          };
          const identity=await readHost();
          const currentHost=async({signal})=>{const current=await readHost(signal);if(Object.keys(identity).some(key=>current[key]!==identity[key]))throw engineError('ON_AI_PROVISIONING_PENDING','');};
          const service=createVaultOnAiService({enabled:true,vault:createNativeOperationVault(nativeHost,nativeOperation),timeoutMs:remaining(),
            appAuthorization:nativeConfiguration.fetchImpl?{fetchImpl:nativeConfiguration.fetchImpl}:{}});
          const options=Object.freeze({signal:lifetime.signal,
            expectedScope:Object.freeze({subjectId:identity.subjectId,projectId:identity.projectId,appId:'aleph-on',audience:'on-client'}),
            expectedContext:Object.freeze({alephUserId:identity.alephUserId,siteId:identity.siteId,identityVersion:identity.identityVersion}),
            beforeDispatch:currentHost,beforePublish:currentHost});
          const raw=await bounded(()=>service.checkConnection(options));
          const capture=(value,keys)=>{
            if(value===null||typeof value!=='object'||types.isProxy(value)||Object.getPrototypeOf(value)!==Object.prototype)throw engineError('SERVICE_UNAVAILABLE','');
            const descriptors=Object.getOwnPropertyDescriptors(value);
            if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(key=>!Object.hasOwn(descriptors,key)||!Object.hasOwn(descriptors[key],'value')))throw engineError('SERVICE_UNAVAILABLE','');
            return Object.fromEntries(keys.map(key=>[key,descriptors[key].value]));
          };
          if(raw===null||typeof raw!=='object'||types.isProxy(raw))throw engineError('SERVICE_UNAVAILABLE','');
          const ok=Object.getOwnPropertyDescriptor(raw,'ok');
          if(!ok||!Object.hasOwn(ok,'value')||typeof ok.value!=='boolean')throw engineError('SERVICE_UNAVAILABLE','');
          if(ok.value===false){
            const output=capture(raw,['ok','error','help']),error=capture(output.error,['code','message']);
            const code=Object.hasOwn(aiErrorMessages,error.code)?error.code:'WB_CLCO_REQUEST_FAILED';
            assertAlive();send(503,{ok:false,error:{code,message:aiErrorMessages[code],retryable:AI_RETRYABLE.has(code)}});return;
          }
          const output=capture(raw,['ok','transportChecked','audienceAuthorization','modelCount','authorizationValidUntilMs','help']);
          if(output.transportChecked!==true||output.audienceAuthorization!=='verified'||!Number.isSafeInteger(output.modelCount)||output.modelCount<1||output.modelCount>64)throw engineError('SERVICE_UNAVAILABLE','');
          const help=aiHelp({audienceAuthorization:'verified',help:capture(output.help,['component','code','appCredentialsConfigured','provisioning','automaticRetries','workbenchRequiredAtRuntime'])});
          if(!Number.isSafeInteger(output.authorizationValidUntilMs)||output.authorizationValidUntilMs<=Date.now())throw engineError('ON_AI_PROVISIONING_PENDING','');
          // Finish metadata/serialization before the last synchronous proof and deadline checks.
          // This proves only app model access; no SDP identity is inferred.
          const body=JSON.stringify({ok:true,data:{transportChecked:true,audienceAuthorization:'verified',modelCount:output.modelCount,help},meta:meta()});
          assertAlive();try{assertNativeHostOperation(nativeHost,nativeOperation);}catch{throw engineError('ON_AI_PROVISIONING_PENDING','');}
          if(output.authorizationValidUntilMs<=Date.now())throw engineError('ON_AI_PROVISIONING_PENDING','');
          assertAlive();
          res.writeHead(200,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','x-on-request-id':requestId});res.end(body);return;
        }finally{closeNativeHostOperation(nativeOperation);}
      }
      if(req.method==='POST'&&url.pathname==='/api/ai/check'){
        await bounded(()=>jsonBody(req,[]));
        const {source}=await captureSource();const binding=await readMapping(source);
        const output=await bounded(()=>mappedService().checkConnection(authOptions(binding)));
        await finishMapping(source,binding);
        if(!output?.ok){send(503,{ok:false,error:aiFailure(output)});return;}
        if(output.transportChecked!==true||!['verified','test'].includes(output.audienceAuthorization)||!Number.isSafeInteger(output.modelCount)||output.modelCount<0)
          throw engineError('SERVICE_UNAVAILABLE','');
        send(200,{ok:true,data:{transportChecked:true,audienceAuthorization:output.audienceAuthorization,modelCount:output.modelCount,help:aiHelp(output)}});return;
      }
      if(req.method==='POST'&&url.pathname==='/api/learner-support'){
        if(Number(req.headers['content-length']??0)>8192)throw engineError('REQUEST_TOO_LARGE','',413);
        const input=await bounded(()=>jsonBody(req,['problemKind'],(key,value)=>isLearnerSupportProblemKind(value)));
        const guide=await bounded(signal=>buildLocalLearnerSupportGuide(input,
          readLocalLearnerSupportObservation(mode,mappedAi??defaultAi),{signal}));
        assertAlive();send(200,{ok:true,data:guide});return;
      }
      if(req.method==='POST'&&url.pathname==='/api/learner-support/gpt'){
        if(!Number.isSafeInteger(aiTimeoutMs)||aiTimeoutMs<=0||aiTimeoutMs>120000){
          send(503,{ok:false,error:{code:'WB_CLCO_INVALID_LIMIT',message:aiErrorMessages.WB_CLCO_INVALID_LIMIT,retryable:false}});return;
        }
        // One route deadline includes body, host identity, vault, pre/post auth and transport.
        supportDeadline={wall:Date.now()+aiTimeoutMs,monotonic:performance.now()+aiTimeoutMs};
        supportTimer=setTimeout(()=>{requestTimedOut=true;lifetime.abort();},aiTimeoutMs);
        if(Number(req.headers['content-length']??0)>8192)throw engineError('REQUEST_TOO_LARGE','',413);
        const input=await bounded(()=>jsonBody(req,['problemKind'],(_key,value)=>isLearnerSupportProblemKind(value)));
        let nativeOperation=null;
        if(nativeHost){try{nativeOperation=await bounded(signal=>openNativeHostOperation(nativeHost,{signal,timeoutMs:aiTimeoutMs}));}catch{throw engineError('ON_AI_PROVISIONING_PENDING','');}}
        try{
        const readHost=async(signal=lifetime.signal)=>{
          if(nativeHost){if(signal?.aborted)throw engineError('REQUEST_CANCELLED','');try{const value=await bounded(()=>readNativeHostOperation(nativeHost,nativeOperation));assertAlive();return value;}catch(error){if(['REQUEST_TIMEOUT','REQUEST_CANCELLED'].includes(error?.code))throw error;throw engineError('ON_AI_PROVISIONING_PENDING','');}}
          if(!readLearnerSupportIdentity)throw engineError('ON_AI_PROVISIONING_PENDING','');
          let raw;try{raw=await bounded(()=>readLearnerSupportIdentity({signal}));}
          catch(error){if(['REQUEST_TIMEOUT','REQUEST_CANCELLED'].includes(error?.code))throw error;throw engineError('ON_AI_PROVISIONING_PENDING','');}
          if(raw===null||typeof raw!=='object'||types.isProxy(raw)||![Object.prototype,null].includes(Object.getPrototypeOf(raw)))throw engineError('ON_AI_PROVISIONING_PENDING','');
          const keys=['subjectId','alephUserId','siteId','identityVersion','projectId'],descriptors=Object.getOwnPropertyDescriptors(raw);
          if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(key=>!Object.hasOwn(descriptors,key)||!Object.hasOwn(descriptors[key],'value')))throw engineError('ON_AI_PROVISIONING_PENDING','');
          const hostIdentity=Object.freeze(Object.fromEntries(keys.map(key=>[key,descriptors[key].value])));
          if(!canonicalSubject(hostIdentity.subjectId)||!opaque(hostIdentity.alephUserId)||!opaque(hostIdentity.siteId)||!opaque(hostIdentity.projectId)
            ||!Number.isSafeInteger(hostIdentity.identityVersion)||hostIdentity.identityVersion<=0)throw engineError('ON_AI_PROVISIONING_PENDING','');
          assertAlive();return hostIdentity;
        };
        const identity=await readHost(),service=nativeHost?createVaultOnAiService({enabled:true,vault:createNativeOperationVault(nativeHost,nativeOperation),timeoutMs:aiTimeoutMs,
          appAuthorization:nativeConfiguration.fetchImpl?{fetchImpl:nativeConfiguration.fetchImpl}:{}}):mappedService();
        const observation=readLocalLearnerSupportObservation(mode,service);
        const prepared=prepareLearnerSupportRequest(input,observation,{signal:lifetime.signal});
        if(service===null||typeof service!=='object'||types.isProxy(service))throw engineError('ON_AI_PROVISIONING_PENDING','');
        const method=Object.getOwnPropertyDescriptor(service,'explainLearningSupport');
        if(!method||!Object.hasOwn(method,'value')||typeof method.value!=='function'||types.isProxy(method.value))throw engineError('ON_AI_PROVISIONING_PENDING','');
        const options={signal:lifetime.signal,expectedScope:Object.freeze({subjectId:identity.subjectId,projectId:identity.projectId,appId:'aleph-on',audience:'on-client'}),
          expectedContext:Object.freeze({alephUserId:identity.alephUserId,siteId:identity.siteId,identityVersion:identity.identityVersion}),
          beforeDispatch:async({signal})=>{const current=await readHost(signal);if(Object.keys(identity).some(key=>current[key]!==identity[key]))throw engineError('ON_AI_PROVISIONING_PENDING','');},
          beforePublish:async({signal})=>{const current=await readHost(signal);if(Object.keys(identity).some(key=>current[key]!==identity[key]))throw engineError('ON_AI_PROVISIONING_PENDING','');}};
        const output=await bounded(()=>Reflect.apply(method.value,service,[input,observation,options]));
        if(output===null||typeof output!=='object'||types.isProxy(output))throw engineError('SERVICE_UNAVAILABLE','');
        const descriptors=Object.getOwnPropertyDescriptors(output);
        if(Reflect.ownKeys(descriptors).some(key=>typeof key!=='string'||!Object.hasOwn(descriptors[key],'value')))throw engineError('SERVICE_UNAVAILABLE','');
        if(!Object.hasOwn(descriptors,'ok')||descriptors.ok.value!==true){
          const error=Object.hasOwn(descriptors,'error')?descriptors.error.value:null;
          if(error===null||typeof error!=='object'||types.isProxy(error)||Object.getPrototypeOf(error)!==Object.prototype)throw engineError('SERVICE_UNAVAILABLE','');
          const errorFields=Object.getOwnPropertyDescriptors(error);
          if(Reflect.ownKeys(errorFields).length!==2||['code','message'].some(key=>!Object.hasOwn(errorFields,key)||!Object.hasOwn(errorFields[key],'value')))throw engineError('SERVICE_UNAVAILABLE','');
          const code=Object.hasOwn(aiErrorMessages,errorFields.code.value)?errorFields.code.value:'WB_CLCO_REQUEST_FAILED';
          send(503,{ok:false,error:{code,message:aiErrorMessages[code],retryable:true}});return;
        }
        const keys=['ok','transportChecked','audienceAuthorization','guide','help','authorizationValidUntilMs'];
        if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(key=>!Object.hasOwn(descriptors,key))
          ||descriptors.transportChecked.value!==true||descriptors.audienceAuthorization.value!=='verified')throw engineError('SERVICE_UNAVAILABLE','');
        const guide=validateLearnerSupportGuide(prepared,descriptors.guide.value,{signal:lifetime.signal});
        const help=descriptors.help.value;
        if(help===null||typeof help!=='object'||types.isProxy(help)||Object.getPrototypeOf(help)!==Object.prototype)throw engineError('SERVICE_UNAVAILABLE','');
        const helpKeys=['component','code','appCredentialsConfigured','provisioning','automaticRetries','workbenchRequiredAtRuntime'],helpFields=Object.getOwnPropertyDescriptors(help);
        if(Reflect.ownKeys(helpFields).length!==helpKeys.length||helpKeys.some(key=>!Object.hasOwn(helpFields,key)||!Object.hasOwn(helpFields[key],'value')))throw engineError('SERVICE_UNAVAILABLE','');
        aiHelp({audienceAuthorization:'verified',help:Object.fromEntries(helpKeys.map(key=>[key,helpFields[key].value]))});
        if(!Number.isSafeInteger(descriptors.authorizationValidUntilMs.value)||descriptors.authorizationValidUntilMs.value<=Date.now())throw engineError('ON_AI_PROVISIONING_PENDING','');
        assertAlive();if(nativeHost)try{assertNativeHostOperation(nativeHost,nativeOperation);}catch{throw engineError('ON_AI_PROVISIONING_PENDING','');}
        if(descriptors.authorizationValidUntilMs.value<=Date.now())throw engineError('ON_AI_PROVISIONING_PENDING','');
        assertAlive();
        send(200,{ok:true,data:guide});return;
        }finally{closeNativeHostOperation(nativeOperation);}
      }
      if(req.method==='GET'&&url.pathname==='/api/diagnostics'){
        // 자동 호출이나 비밀 원문·전체 설정 출력 없이 로컬 연결 상태와 일반 권한 내 PC 상태를 함께 진단한다.
        const info=(mappedAi??defaultAi).connectionInfo();
        const checkedAtNow=clock().toISOString();
        const pcTelemetry=await bounded(()=>collectLocalPcTelemetry(assetsRoot,checkedAtNow));
        send(200,{ok:true,data:{requestId,component:'on-client',version:'0.1.0',engine:{mode,code:mode==='disconnected'?'ENGINE_NOT_CONNECTED':mode==='demo'?'DEMO_ONLY':'ADAPTER_CONFIGURED'},
          ai:{configured:info?.configured===true,authorized:false,authorizationRequired:true},checkedAt:checkedAtNow,workbenchRequiredAtRuntime:false,pcTelemetry}});return;
      }
      if(req.method==='GET'&&url.pathname==='/api/vulnerabilities'){
        const data=await bounded(signal=>scanner.scan({signal}));send(200,{ok:true,data});
        return;
      }
      send(404,{ok:false,error:{code:'NOT_FOUND',message:'지원하지 않는 주소입니다.',retryable:false}});
    }catch(error){
      if(actionRequest&&error?.code==='REQUEST_TIMEOUT'){
        const projected=projectAction({ok:false,error:{code:'ACTION_TIMEOUT'}},'result',{});send(projected.status,projected.body);return;
      }
      const code=Object.hasOwn(safeErrors,error?.code)?error.code:'SERVICE_UNAVAILABLE';
      const [status,message]=safeErrors[code];
      send(status,{ok:false,error:{code,message,retryable:nativeAiCheck?AI_RETRYABLE.has(code):status>=500}});
    }finally{clearTimeout(requestTimer);clearTimeout(supportTimer);res.removeListener('close',disconnect);req.removeListener('aborted',disconnect);lifetime.abort();}
  });
  server.requestTimeout=15000;server.headersTimeout=10000;
  server.once('close',()=>{connections.close();nativeHost?.close();for(const controller of connectionReads)controller.abort();});
  return server;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const args=process.argv.slice(2);let demo=false,actions=false,nativePath,sdpPath,actionsPath;
  for(let i=0;i<args.length;i++){
    if(args[i]==='--demo'){demo=true;continue;}
    // C4: 조치는 --alekov-actions 와 --alekov-actions-config <절대경로> 를 함께 줄 때만 켠다. 각각 한 번만 받는다.
    if(args[i]==='--alekov-actions'&&!actions){actions=true;continue;}
    if(args[i]==='--native-host-config'&&nativePath===undefined&&typeof args[i+1]==='string'&&!args[i+1].startsWith('--')){nativePath=args[++i];continue;}
    if(args[i]==='--sdp-host-config'&&sdpPath===undefined&&typeof args[i+1]==='string'&&!args[i+1].startsWith('--')){sdpPath=args[++i];continue;}
    if(args[i]==='--alekov-actions-config'&&actionsPath===undefined&&typeof args[i+1]==='string'&&!args[i+1].startsWith('--')){actionsPath=args[++i];continue;}
    throw Error('UNKNOWN_ARGUMENT');
  }
  if(demo&&sdpPath!==undefined)throw Error('SDP_HOST_DEMO_CONFLICT');
  // 자원(native context·SDP host)을 만들기 전에 조합을 모두 거절한다: 한쪽만 준 경우, demo, native·SDP 설정 누락.
  if(actions!==(actionsPath!==undefined))throw Error('ACTION_STARTUP_INCOMPLETE');
  if(actions&&(demo||nativePath===undefined||sdpPath===undefined))throw Error('ACTION_STARTUP_CONFLICT');
  // 조치 설정은 파일 읽기만 하므로 native helper(registry·ACL 검사)를 부르기 전에 먼저 닫힌 schema 로 확인한다.
  const actionStartup=actions?readActionStartupConfiguration(actionsPath):null;
  const nativeHostConfiguration=nativePath===undefined?undefined:await readNativeHostConfiguration(nativePath);
  const port=Number(process.env.ON_PORT??5189);
  if(!Number.isInteger(port)||port<1024||port>65535)throw Error('INVALID_PORT');
  const sdpHost=sdpPath===undefined?null:createSdpHostEngine(await readSdpHostConfiguration(sdpPath,{projectRoot:resolve(root)}));
  let server;
  try{
    // 학생 모듈에는 본인 범위의 조회·판정 기능만 전달한다. 비밀·설정·종료·조치 기능은 호스트에 둔다(C4 도 이 목록을 늘리지 않는다).
    const hostCapability=sdpHost?Object.freeze({projectId:sdpHost.projectId,
      readIdentity:sdpHost.readIdentity.bind(sdpHost),readApps:sdpHost.readApps.bind(sdpHost),decideAccess:sdpHost.decideAccess.bind(sdpHost),
      readEvents:sdpHost.readEvents.bind(sdpHost),readDevices:sdpHost.readDevices.bind(sdpHost),readSessions:sdpHost.readSessions.bind(sdpHost)}):undefined;
    const engine=demo?demoEngine():await loadEngine(process.env.ON_ENGINE_ADAPTER??(sdpHost?resolve(root,'student/engine-adapter.mjs'):undefined),{hostCapability});
    let approvedPublicPackages=[];
    if(process.env.ON_APPROVED_PUBLIC_PACKAGES){try{approvedPublicPackages=JSON.parse(process.env.ON_APPROVED_PUBLIC_PACKAGES);}catch{throw Error('INVALID_PUBLIC_PACKAGE_LIST');}if(!Array.isArray(approvedPublicPackages))throw Error('INVALID_PUBLIC_PACKAGE_LIST');}
    const scanner=createProjectScanner({projectDirectory:process.env.ON_PROJECT_DIRECTORY,approvedPublicPackages});
    // 같은 createOnServer 안의 nativeHost 와 같은 owned sdpHost 만 조치 설정에 쓰인다(constructor 215–224행).
    server=createOnServer({engine,scanner,...(nativeHostConfiguration?{nativeHostConfiguration}:{}),...(sdpHost?{sdpHostEngine:sdpHost}:{}),
      ...(actionStartup?{sdpActionStartup:actionStartup.sdpActionStartup}:{})});
  }catch(error){sdpHost?.close();throw error;}
  if(sdpHost){server.once('close',()=>sdpHost.close());server.once('error',()=>sdpHost.close());}
  server.listen(port,'127.0.0.1',()=>console.log(`케셰브 ${demo?'예제':'연결 확인'}: http://127.0.0.1:${port}`));
}

'@
  [IO.File]::WriteAllText($SrvTarget, $SrvContent, (New-Object System.Text.UTF8Encoding($false)))
  Write-Host "[반영 완료] $SrvTarget (내 PC CPU·메모리·디스크·방화벽·Windows 기록 실측 확장 포함)" -ForegroundColor Green
} else {
  Write-Host "[안내] 제공 서버 파일(src\server.mjs)은 원본 그대로 유지했습니다. (로컬 PC 하드웨어·방화벽 실측 API까지 켜려면 뒤에 -IncludeServerTelemetry 를 붙여 실행하세요)" -ForegroundColor Yellow
}

# 7. 문법 검사 실행
$NodeCmd = Get-Command node -ErrorAction SilentlyContinue
if ($NodeCmd) {
  & node --check $ExtTarget
  if ($LASTEXITCODE -eq 0) {
    Write-Host "[문법 검증 통과] node --check student/extension.mjs (ExitCode: 0)" -ForegroundColor Green
  }
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " 모든 파일이 내 PC의 $OnClient 에 반영되었습니다!" -ForegroundColor Cyan
Write-Host " 이제 아래 명령으로 서버를 켜서 확인하세요:" -ForegroundColor Cyan
Write-Host " cd `"$OnClient`"" -ForegroundColor White
Write-Host " powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Cyan
