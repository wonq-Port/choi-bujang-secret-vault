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

  const secretPattern = /(?:Bearer\s+\S+|sk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{8,}|github_pat_\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_ -]?key|authorization|password|secret|token|비밀번호|토큰|열쇠)\s*[:=]\s*\S+)/i;

  const sanitizeText = (value, fallback = '확인 불가') => {
    if (typeof value !== 'string' || value.trim().length === 0) return fallback;
    if (secretPattern.test(value)) return '[보안상 민감정보 생략]';
    return value.trim();
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
        addText(root, 'p', '보안 기록을 불러오는 중입니다.');
        return root;
      }

      if (status === 'error') {
        eventFilters = { kind: 'all', appId: 'all', access: 'all' };
        selectedEventId = null;
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
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
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

      // 1) explanation.status가 error이면 event가 null이어도 안전한 오류 코드·메시지와 실패 이유를 먼저 표시
      if (status === 'error') {
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
        addText(root, 'p', `사건 ID: ${eventId} · 선택한 기록의 AI 설명을 요청하는 중입니다.`);
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
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
