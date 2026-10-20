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

          if (Array.isArray(selectedEvent.supportedActions) && selectedEvent.supportedActions.length > 0) {
            addText(detailBox, 'h5', '미지원 조치 안내');
            addText(detailBox, 'p', '아래 조치는 이 학생 화면에서 실행되지 않습니다. 조치 실행 연결은 준비 중입니다.');
            const unsupportedActions = document.createElement('div');
            for (const action of selectedEvent.supportedActions) {
              if (typeof action !== 'string' || action.length === 0) continue;
              const unsupportedButton = document.createElement('button');
              unsupportedButton.type = 'button';
              unsupportedButton.textContent = `${action} 미지원`;
              unsupportedButton.setAttribute('aria-label', `${action} 미지원`);
              unsupportedButton.disabled = true;
              unsupportedActions.append(unsupportedButton);
            }
            if (unsupportedActions.childNodes.length > 0) detailBox.append(unsupportedActions);
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
      const valueText = (value) => typeof value === 'string' && value.trim().length > 0
        ? value
        : '확인 불가';
      const modeLabels = {
        connected: '연결됨',
        demo: '예제 자료',
        disconnected: '연결 없음',
        unknown: '확인 불가',
      };
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
      const statusLabel = (value, labels) => Object.hasOwn(labels, value)
        ? labels[value]
        : '확인 불가';
      const isUnverified = (error) =>
        ['CONTRACT_MISMATCH', 'ENGINE_RESULT_UNVERIFIED'].includes(error?.code);
      const isTimeout = (error) =>
        /TIME.?OUT|TIMED.?OUT/i.test(String(error?.code ?? ''))
        || /시간\s*초과|timed?\s*out|timeout/i.test(String(error?.message ?? ''));
      const modeText = Object.hasOwn(modeLabels, mode)
        ? `${modeLabels[mode]} (${mode})`
        : `확인 불가 (${valueText(mode)})`;

      addText(root, 'h3', '기기·세션·알림·연결 진단 상태');
      addText(root, 'p', `연결 상태: ${modeText}`);

      const renderListResource = (title, resource, kind) => {
        const block = document.createElement('section');
        root.append(block);
        addText(block, 'h4', title);
        const current = resource && typeof resource === 'object' ? resource : {};
        if (current.status === 'loading') {
          addText(block, 'p', `${title}: 불러오는 중`);
          return;
        }
        if (current.status === 'error') {
          const error = current.error && typeof current.error === 'object' ? current.error : {};
          const message = valueText(error.message);
          if (isTimeout(error)) {
            addText(block, 'p', `${title} 조회 시간 초과: ${message}`);
          } else if (isUnverified(error)) {
            addText(block, 'p', `${title} 조회 결과 확인 불가: ${message}`);
          } else {
            addText(block, 'p', `${title} 정보를 불러오지 못했습니다: ${message}`);
          }
          addText(block, 'p', '다시 시도하려면 위쪽 「다시 불러오기」 버튼을 직접 누르세요. 자동으로 다시 요청하지 않습니다.');
          return;
        }
        if (current.status !== 'ok') {
          addText(block, 'p', `${title} 상태를 확인할 수 없습니다. 목록이 비어 있다는 의미는 아닙니다.`);
          return;
        }
        if (!Array.isArray(current.data)) {
          addText(block, 'p', `${title} 응답 형식을 확인할 수 없어 목록을 표시하지 않습니다.`);
          return;
        }
        if (current.data.length === 0) {
          addText(block, 'p', kind === 'devices' ? '등록된 기기가 없습니다.' : '현재 연결이 없습니다.');
          return;
        }
        const labels = kind === 'devices' ? deviceLabels : sessionLabels;
        const list = document.createElement('ul');
        for (const item of current.data) {
          const row = document.createElement('li');
          if (kind === 'devices') {
            const originalStatus = valueText(item?.status);
            const readableStatus = statusLabel(item?.status, labels);
            row.textContent = `기기: ${valueText(item?.label)} · 상태: ${readableStatus} (${originalStatus})`;
          } else {
            const originalStatus = valueText(item?.status);
            const readableStatus = statusLabel(item?.status, labels);
            row.textContent = `세션 ID: ${valueText(item?.id)} · 상태: ${readableStatus} (${originalStatus})`;
          }
          list.append(row);
        }
        block.append(list);
      };

      renderListResource('기기', devices, 'devices');
      renderListResource('세션', sessions, 'sessions');
      addText(root, 'p', '세션 조회 범위: 현재 검증된 연결 한 개입니다. 과거 세션 전체 목록이 아닙니다.');

      const notificationBlock = document.createElement('section');
      root.append(notificationBlock);
      addText(notificationBlock, 'h4', '알림');
      if (!Array.isArray(notifications)) {
        addText(notificationBlock, 'p', '알림 자료를 확인할 수 없습니다.');
      } else if (notifications.length === 0) {
        addText(notificationBlock, 'p', '주의할 알림이 없습니다.');
      } else {
        const list = document.createElement('ul');
        for (const notification of notifications) {
          const item = document.createElement('li');
          const code = typeof notification?.code === 'string'
            && /^[A-Za-z0-9_.:-]{1,80}$/.test(notification.code)
            ? notification.code
            : '확인 불가';
          item.textContent = `자료(resource): ${valueText(notification?.resource)} · 코드(code): ${code} · 메시지: ${valueText(notification?.message)}`;
          list.append(item);
        }
        notificationBlock.append(list);
      }

      const diagnosticBlock = document.createElement('section');
      root.append(diagnosticBlock);
      addText(diagnosticBlock, 'h4', '연결 진단 정보');
      const currentDiagnostics = diagnostics && typeof diagnostics === 'object' ? diagnostics : {};
      if (currentDiagnostics.status === 'loading') {
        addText(diagnosticBlock, 'p', '도움정보를 불러오는 중입니다.');
      } else if (currentDiagnostics.status === 'error') {
        const error = currentDiagnostics.error && typeof currentDiagnostics.error === 'object'
          ? currentDiagnostics.error
          : {};
        const message = valueText(error.message);
        if (isTimeout(error)) {
          addText(diagnosticBlock, 'p', `도움정보 조회 시간 초과: ${message}`);
        } else if (isUnverified(error)) {
          addText(diagnosticBlock, 'p', `도움정보 조회 결과 확인 불가: ${message}`);
        } else {
          addText(diagnosticBlock, 'p', `도움정보를 불러오지 못했습니다: ${message}`);
        }
        addText(diagnosticBlock, 'p', '다시 조회하려면 제공 화면의 「도움정보 불러오기」 버튼을 직접 누르세요. 자동으로 다시 요청하지 않습니다.');
      } else if (currentDiagnostics.status === 'ok') {
        const data = currentDiagnostics.data && typeof currentDiagnostics.data === 'object'
          ? currentDiagnostics.data
          : {};
        const engine = data.engine && typeof data.engine === 'object' ? data.engine : {};
        // 진단 결과에서 허용된 필드만 구성한다. 원본 객체 전체는 표시하거나 복사하지 않는다.
        const safeDiagnostics = {
          requestId: valueText(data.requestId),
          component: valueText(data.component),
          version: valueText(data.version),
          checkedAt: valueText(data.checkedAt),
          engine: {
            mode: valueText(engine.mode),
            code: valueText(engine.code),
          },
        };
        for (const [key, value] of Object.entries(safeDiagnostics)) {
          if (key === 'engine') {
            addText(diagnosticBlock, 'p', `engine.mode: ${value.mode}`);
            addText(diagnosticBlock, 'p', `engine.code: ${value.code}`);
          } else {
            addText(diagnosticBlock, 'p', `${key}: ${value}`);
          }
        }
        addText(diagnosticBlock, 'p', '도움 요청에 필요한 제한된 진단 정보입니다. 비밀번호·토큰·API 키를 포함한 전체 설정은 표시하거나 복사하지 않습니다.');
        const copyStatus = addText(diagnosticBlock, 'p', '복사 전입니다. 버튼을 누를 때만 위의 허용된 진단 필드를 복사합니다.');
        copyStatus.setAttribute('aria-live', 'polite');
        const copyButton = document.createElement('button');
        copyButton.type = 'button';
        copyButton.textContent = '도움정보 복사';
        copyButton.setAttribute('aria-label', '도움정보 복사');
        copyButton.addEventListener('click', async () => {
          try {
            if (typeof navigator === 'undefined' || !navigator.clipboard
              || typeof navigator.clipboard.writeText !== 'function') {
              throw new Error('CLIPBOARD_UNAVAILABLE');
            }
            await navigator.clipboard.writeText(JSON.stringify(safeDiagnostics, null, 2));
            copyStatus.textContent = '허용된 진단 정보를 클립보드에 복사했습니다.';
          } catch {
            copyStatus.textContent = '클립보드에 복사하지 못했습니다. 브라우저의 클립보드 권한을 확인하세요.';
          }
        });
        diagnosticBlock.append(copyButton);
      } else {
        addText(diagnosticBlock, 'p', '도움정보가 아직 조회되지 않았습니다. 제공 화면의 「도움정보 불러오기」 버튼을 눌러 조회하세요.');
      }

      return root;
    },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
