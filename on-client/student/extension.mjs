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
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}