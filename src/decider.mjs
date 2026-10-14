export const RULE_IDS = Object.freeze([
  'starter.deny',
  'device_registered',
  'step_up_required',
]);

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

  if (needsStepUp(request)) {
    if (isStepUpVerified(request?.stepUp)) {
      return {
        schema: 'aleph.decision.v1',
        requestId,
        decision: 'allow',
        reasonCode: 'approved',
        ruleIds: ['device_registered', 'step_up_required'],
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
    ruleIds: ['device_registered'],
  };
}
