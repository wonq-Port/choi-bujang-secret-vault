export const RULE_IDS = Object.freeze([
  'starter.deny',
  'device_registered',
  'step_up_required',
  'zone_access',
]);

const RESERVED_IDS = new Set([
  'export',
  'import',
  'all',
  'list',
  'search',
  'query',
  'bulk',
  'batch',
  'dump',
  'backup',
  'restore',
  'admin',
  'instructor',
  'teacher',
  'staff',
  'notices',
  'notice',
  'announcements',
  'announcement',
  'config',
  'settings',
  'status',
  'health',
  'debug',
  'raw',
  'download',
  'upload',
]);

const NOTE_SERVICES = new Set(['notes', 'note', 'memos', 'memo', 'vault']);
const NOTICE_SERVICES = new Set([
  'notices',
  'notice',
  'announcements',
  'announcement',
  'class_notices',
  'class-notices',
  'board',
]);
const INSTRUCTOR_SERVICES = new Set([
  'instructor',
  'teacher',
  'admin',
  'staff',
  'faculty',
  'grading',
  'management',
]);

const NOTE_ITEM_PATH = /^\/(?:api\/)?(?:notes?|memos?)\/([^/?#]+)$/u;
const NOTE_ITEM_ROUTE = /^(GET|PUT|PATCH|DELETE) \/(?:api\/)?(?:notes?|memos?)\/:[A-Za-z0-9_]+$/u;

const NOTICE_PATH = /^\/(?:api\/)?(?:class[-_])?(?:notices?|announcements?)(?:\/([^/?#]+))?$/u;
const NOTICE_ROUTE = /^(GET|POST|PUT|PATCH|DELETE) \/(?:api\/)?(?:class[-_])?(?:notices?|announcements?)(?:\/:[A-Za-z0-9_]+)?$/u;

const INSTRUCTOR_PATH = /^\/(?:api\/)?(?:instructor|teacher|admin|staff|faculty|grading)(?:\/.*)?$/iu;

function checkZoneAccess(request) {
  const service = typeof request?.service === 'string' ? request.service.trim().toLowerCase() : '';
  const method = typeof request?.method === 'string' ? request.method.trim().toUpperCase() : '';
  const path = typeof request?.path === 'string' ? request.path.trim() : '';
  const route = typeof request?.route === 'string' ? request.route.trim() : '';

  if (!service || !method || !path || !route) {
    return { allowed: false, reasonCode: 'invalid_route' };
  }

  // 쿼리로 기능을 고르는 요청 거부
  if (typeof request?.queryLength !== 'number' || request.queryLength !== 0) {
    return { allowed: false, reasonCode: 'query_not_allowed' };
  }

  // 강사 자료 구역은 판정기에서 모두 거부
  if (
    INSTRUCTOR_SERVICES.has(service) ||
    INSTRUCTOR_PATH.test(path) ||
    route.includes('/instructor') ||
    route.includes('/teacher') ||
    route.includes('/admin')
  ) {
    return { allowed: false, reasonCode: 'instructor_zone_denied' };
  }

  // 반 공지 구역: 읽기(GET)만 허용, 쓰기(POST·PUT·PATCH·DELETE)는 모두 거부
  const noticePathMatch = NOTICE_PATH.exec(path);
  const noticeRouteMatch = NOTICE_ROUTE.exec(route);
  if (NOTICE_SERVICES.has(service) || noticePathMatch || noticeRouteMatch) {
    if (!noticePathMatch || !noticeRouteMatch || noticeRouteMatch[1] !== method) {
      return { allowed: false, reasonCode: 'invalid_notice_route' };
    }
    const noticeId = noticePathMatch[1];
    if (noticeId !== undefined) {
      if (noticeId === '.' || noticeId === '..' || RESERVED_IDS.has(noticeId.toLowerCase())) {
        return { allowed: false, reasonCode: 'reserved_route_denied' };
      }
      if (!route.endsWith('/:id')) {
        return { allowed: false, reasonCode: 'invalid_notice_route' };
      }
    } else if (route.endsWith('/:id')) {
      return { allowed: false, reasonCode: 'invalid_notice_route' };
    }
    if (method !== 'GET') {
      return { allowed: false, reasonCode: 'notice_write_denied' };
    }
    return { allowed: true };
  }

  // 메모 구역: 자료 ID 하나를 고르는 경로만 허용하고 ID 없는 전체 목록 경로는 거부
  if (NOTE_SERVICES.has(service)) {
    const notePathMatch = NOTE_ITEM_PATH.exec(path);
    const noteRouteMatch = NOTE_ITEM_ROUTE.exec(route);
    if (!notePathMatch || !noteRouteMatch || noteRouteMatch[1] !== method) {
      return { allowed: false, reasonCode: 'note_collection_or_unknown_denied' };
    }
    const noteId = notePathMatch[1];
    if (
      !noteId ||
      noteId === '.' ||
      noteId === '..' ||
      RESERVED_IDS.has(noteId.toLowerCase())
    ) {
      return { allowed: false, reasonCode: 'reserved_route_denied' };
    }
    return { allowed: true };
  }

  // 알 수 없는 서비스나 경로는 모두 거부
  return { allowed: false, reasonCode: 'unknown_zone_denied' };
}

function isStepUpVerified(stepUp) {
  return Boolean(
    stepUp &&
    typeof stepUp === 'object' &&
    stepUp.verified === true &&
    typeof stepUp.authAgeSeconds === 'number' &&
    Number.isFinite(stepUp.authAgeSeconds) &&
    stepUp.authAgeSeconds >= 0 &&
    stepUp.authAgeSeconds <= 900
  );
}

function isStepUpFormatValid(stepUp) {
  if (!stepUp || typeof stepUp !== 'object') return false;
  if (stepUp.verified === false) return stepUp.authAgeSeconds === null;
  if (stepUp.verified === true) {
    return (
      typeof stepUp.authAgeSeconds === 'number' &&
      Number.isFinite(stepUp.authAgeSeconds) &&
      stepUp.authAgeSeconds >= 0 &&
      stepUp.authAgeSeconds <= 900
    );
  }
  return false;
}

function needsStepUp(request) {
  if (!isStepUpFormatValid(request?.stepUp)) {
    return true;
  }

  const signals = request?.signals;
  const recentEvents = request?.recentEvents;

  if (!signals || typeof signals !== 'object' || !Array.isArray(recentEvents)) {
    return true;
  }

  const source = signals.source;
  if (source !== 'none' && source !== 'judge_fixture') {
    return true;
  }

  const hasRiskEvents = recentEvents.some(
    (event) =>
      !event ||
      typeof event !== 'object' ||
      typeof event.count !== 'number' ||
      event.count >= 5 ||
      event.kind === 'risk_signal' ||
      (typeof event.kind === 'string' && event.kind !== 'normal')
  );
  if (hasRiskEvents) {
    return true;
  }

  if (source === 'judge_fixture') {
    const unusualRegion = typeof signals.region !== 'string' || signals.region !== 'local';
    const unusualNetwork = typeof signals.network !== 'string' || signals.network !== 'usual';
    const unusualHour =
      typeof signals.hour !== 'number' ||
      !Number.isFinite(signals.hour) ||
      signals.hour < 6 ||
      signals.hour >= 22;

    if (unusualRegion || unusualNetwork || unusualHour) {
      return true;
    }
  }

  if (source === 'none') {
    if (
      (typeof signals.region === 'string' && signals.region !== 'unknown' && signals.region !== 'local') ||
      (typeof signals.network === 'string' && signals.network !== 'unknown' && signals.network !== 'usual')
    ) {
      return true;
    }
  }

  return false;
}

export async function decide(request) {
  const requestId = typeof request?.requestId === 'string' ? request.requestId : '';

  if (request?.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  const zoneCheck = checkZoneAccess(request);
  if (!zoneCheck.allowed) {
    return {
      schema: 'aleph.decision.v1',
      requestId,
      decision: 'deny',
      reasonCode: zoneCheck.reasonCode,
      ruleIds: ['zone_access'],
    };
  }

  if (needsStepUp(request)) {
    if (isStepUpVerified(request?.stepUp)) {
      return {
        schema: 'aleph.decision.v1',
        requestId,
        decision: 'allow',
        reasonCode: 'approved',
        ruleIds: ['device_registered', 'step_up_required', 'zone_access'],
      };
    }

    return {
      schema: 'aleph.decision.v1',
      requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  return {
    schema: 'aleph.decision.v1',
    requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered', 'zone_access'],
  };
}
