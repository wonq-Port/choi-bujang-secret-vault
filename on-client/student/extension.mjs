// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView({ onChange } = {}) {
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
    renderVulnerabilities({ status, mode, data, error } = {}) {
      // 매 호출마다 새 DOM 요소를 만들어 반환하므로 진행 중(loading)·오류(error)·재조회 시 이전 표가 남지 않음
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
        not_configured: '조회 준비 미완료 · 프로젝트 설정 필요(not_configured)',
        unverifiable: 'lock 파일 확인 불가(unverifiable)',
      };
      const scanStatusGuides = {
        complete: 'package-lock.json과 설치된 node_modules 메타데이터를 대조하여 승인된 공개 패키지의 OSV 취약점 조회를 모두 마쳤습니다. 알려진 취약점 DB 기준 결과이며 패키지나 앱 전체의 안전을 보장하지는 않습니다.',
        partial: '일부 패키지의 OSV 조회에 실패하여 전체 조회를 완료하지 못했습니다(취약점 없음·안전 아님). 이미 확인된 취약점 ID는 지우지 않고 그대로 유지해 표시합니다.',
        not_checked: '승인된 공개 조회 대상 패키지가 없어 OSV 조회를 실행하지 않은 미조회 상태입니다(NO_APPROVED_PACKAGES). 미조회는 취약점 없음(안전)을 뜻하지 않습니다.',
        not_configured: '조회 대상 프로젝트 경로 또는 허용 패키지 설정이 아직 준비되지 않은 미조회 상태입니다(PROJECT_NOT_CONFIGURED). 프로젝트 설정 미비는 취약점 없음(안전)을 뜻하지 않습니다.',
        unverifiable: 'package-lock.json과 설치된 node_modules 메타데이터를 대조·검증할 수 없습니다(LOCKFILE_UNVERIFIABLE). 확인 불가는 취약점 없음(안전)을 뜻하지 않습니다.',
      };

      addText(root, 'h3', '설치 패키지 버전 및 알려진 취약점(OSV) 조회 결과');

      if (mode !== null && mode !== undefined) {
        const modeText = Object.hasOwn(modeLabels, mode) ? modeLabels[mode] : modeLabels.unknown;
        addText(root, 'p', `연결 상태: ${modeText}`);
      }

      if (!status || status === 'idle') {
        addText(
          root,
          'p',
          '조회 전(idle) — 아직 설치 패키지 취약점 조회를 실행하지 않았습니다. 보호 현황의 「설치 패키지 조회」 버튼을 직접 눌러 조회하세요. (미조회 상태는 취약점 없음을 뜻하지 않습니다.)',
        );
        return root;
      }

      if (status === 'loading') {
        addText(
          root,
          'p',
          '조회 중(loading) — package-lock.json과 설치된 node_modules의 정확한 설치 버전을 대조하여 OSV 취약점 정보를 조회하고 있습니다. 이전 조회 표는 표시하지 않습니다.',
        );
        return root;
      }

      if (status === 'error') {
        const safeCode = sanitizeText(error?.code, 'SCAN_ERROR');
        const safeMsg = sanitizeText(error?.message, '패키지 취약점 조회를 완료하지 못했습니다.');
        if (safeCode === 'CANCELLED' || safeCode === 'REQUEST_CANCELLED') {
          addText(
            root,
            'p',
            `조회 실패 · 취소됨(${safeCode}): ${safeMsg} — 취소된 요청이나 이전 결과는 현재 확인 결과가 아니며, 취약점 없음(안전)으로 간주하지 않습니다. 필요하면 「설치 패키지 조회」 버튼을 직접 눌러 다시 조회하세요.`,
          );
        } else if (safeCode === 'TIMEOUT' || safeCode === 'REQUEST_TIMEOUT' || /초과|timeout/i.test(safeMsg)) {
          addText(
            root,
            'p',
            `조회 실패 · 시간 초과(${safeCode}): ${safeMsg} — 응답 시간 초과로 조회가 중단되었습니다. 조회 실패는 취약점 없음(안전)이 아닙니다. 잠시 뒤 「설치 패키지 조회」 버튼을 직접 눌러 다시 조회하세요.`,
          );
        } else {
          addText(
            root,
            'p',
            `조회 실패(${safeCode}): ${safeMsg} — 조회 실패는 취약점 없음(안전)이 아니며 이전 표를 현재 결과로 남기지 않습니다. 필요하면 「설치 패키지 조회」 버튼을 직접 눌러 다시 조회하세요.`,
          );
        }
        return root;
      }

      if (status !== 'ok' || !data || typeof data !== 'object' || !Object.hasOwn(scanStatusLabels, data.status)) {
        addText(
          root,
          'p',
          '조회 실패(CONTRACT_MISMATCH): 패키지 조회 응답 형식을 확인할 수 없습니다. 결과를 표시하지 않으며 취약점 없음(안전)으로 간주하지 않습니다.',
        );
        return root;
      }

      const scanStatus = data.status;
      addText(root, 'p', `전체 조회 상태: ${scanStatusLabels[scanStatus]}`);
      addText(root, 'p', scanStatusGuides[scanStatus]);

      if (typeof data.code === 'string' && data.code.trim().length > 0) {
        addText(root, 'p', `상태 코드(code): ${sanitizeText(data.code)}`);
      }
      if (data.lockfileVersion !== undefined && data.lockfileVersion !== null) {
        addText(
          root,
          'p',
          `잠금 파일 버전(lockfileVersion): ${String(data.lockfileVersion)} (원천: package-lock.json 및 node_modules 메타데이터 대조)`,
        );
      }
      if (typeof data.lockfileHash === 'string' && data.lockfileHash.trim().length > 0) {
        addText(root, 'p', `잠금 파일 해시(lockfileHash): ${sanitizeText(data.lockfileHash)}`);
      }
      if (typeof data.checkedAt === 'string' && data.checkedAt.trim().length > 0) {
        addText(root, 'p', `조회 시각(checkedAt): ${sanitizeText(data.checkedAt)}`);
      }
      if (data.excluded && typeof data.excluded === 'object') {
        const excludedTotal = Number.isSafeInteger(data.excluded.count)
          ? data.excluded.count
          : (Number.isSafeInteger(data.excluded.unapproved) ? data.excluded.unapproved : 0)
            + (Number.isSafeInteger(data.excluded.unsupported) ? data.excluded.unsupported : 0)
            + (Number.isSafeInteger(data.excluded.invalid) ? data.excluded.invalid : 0);
        addText(root, 'p', `조회 제외 패키지 수: ${String(excludedTotal)}건`);
      }

      const rawPackages = Array.isArray(data.packages) ? data.packages : [];
      if (rawPackages.length === 0) {
        if (scanStatus === 'complete') {
          addText(root, 'p', '조회 대상 패키지 목록이 비어 있습니다. (조회 범위에서 표시할 패키지 결과 없음)');
        } else {
          addText(
            root,
            'p',
            `현재 전체 조회 상태가 ${scanStatusLabels[scanStatus]}이므로 확인된 패키지 표가 없습니다. 미조회·설정 미비·확인 불가는 취약점 없음(안전)이 아닙니다.`,
          );
        }
        return root;
      }

      const table = document.createElement('table');
      const thead = document.createElement('thead');
      const headRow = document.createElement('tr');
      for (const colTitle of ['패키지 이름(name)', '정확한 설치 버전(version)', '조회 상태(status)', '취약점 ID 및 수정 시각(modified)', '출처(source)', '패키지 조회 시각(checkedAt)']) {
        addText(headRow, 'th', colTitle);
      }
      thead.append(headRow);
      table.append(thead);

      const tbody = document.createElement('tbody');
      for (const pkg of rawPackages) {
        const rawName = typeof pkg?.name === 'string' ? pkg.name.trim() : '';
        const rawVersion = typeof pkg?.version === 'string' ? pkg.version.trim() : '';
        const exactVersionOk = isExactSemver(rawVersion);

        const tr = document.createElement('tr');
        if (rawName && !secretPattern.test(rawName)) {
          tr.setAttribute('data-student-package-name', rawName);
        }

        // ^1.2.0 같은 버전 범위는 실제 설치 버전으로 표시하거나 속성에 넣지 않음
        if (exactVersionOk) {
          tr.setAttribute('data-student-package-version', rawVersion);
        }

        addText(tr, 'td', sanitizeText(rawName, '이름 확인 불가'));
        addText(
          tr,
          'td',
          exactVersionOk
            ? rawVersion
            : '설치 버전 확인 불가(unverifiable · 버전 범위는 설치 버전으로 표시하지 않음)',
        );

        const findings = Array.isArray(pkg?.vulnerabilities)
          ? pkg.vulnerabilities.filter(
            (v) => v && typeof v === 'object' && typeof v.id === 'string' && v.id.trim().length > 0,
          )
          : [];

        const pkgStatus = exactVersionOk ? pkg?.status : 'unverifiable';
        let pkgStatusDescription = '';
        if (pkgStatus === 'known_vulnerabilities') {
          pkgStatusDescription = '알려진 항목 있음(known_vulnerabilities)';
        } else if (pkgStatus === 'none_found') {
          pkgStatusDescription = '알려진 항목 없음(none_found) · 조회 범위에서 알려진 항목 없음(앱 전체 안전 보장 아님)';
        } else if (pkgStatus === 'unverifiable' && findings.length > 0) {
          pkgStatusDescription = '일부 확인·전체 조회 확인 불가(unverifiable) · 이미 받은 취약점 ID 유지(취약점 없음 아님)';
        } else {
          pkgStatusDescription = '조회 확인 불가(unverifiable) · 취약점 여부를 확인할 수 없음(취약점 없음·안전 아님)';
        }
        addText(tr, 'td', pkgStatusDescription);

        const vulnCell = document.createElement('td');
        if (findings.length > 0) {
          const vulnList = document.createElement('ul');
          for (const finding of findings) {
            const fId = sanitizeText(finding.id, 'ID 확인 불가');
            const fMod = sanitizeText(finding.modified, '시각 확인 불가');
            addText(vulnList, 'li', `${fId} (수정 시각 modified: ${fMod})`);
          }
          vulnCell.append(vulnList);
        } else if (pkgStatus === 'none_found') {
          vulnCell.textContent = '알려진 항목 없음(none_found)';
        } else {
          vulnCell.textContent = '조회 확인 불가(unverifiable · 취약점 없음 아님)';
        }
        tr.append(vulnCell);

        addText(tr, 'td', sanitizeText(pkg?.source, '출처 확인 불가'));
        addText(tr, 'td', sanitizeText(pkg?.checkedAt, '시각 확인 불가'));

        tbody.append(tr);
      }

      table.append(tbody);
      root.append(table);

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
