import test from 'node:test';
import assert from 'node:assert/strict';

function getDecisionBadge(decision, riskScore) {
  switch (decision) {
    case 'BLOCK':
      return { text: 'ERR', color: '#EF4444', title: `Blocked (${riskScore})` };
    case 'WARN':
      return { text: '!', color: '#F59E0B', title: `Warning (${riskScore})` };
    case 'ALLOW':
    default:
      return { text: riskScore === 0 ? '' : 'OK', color: '#10B981', title: `Safe (${riskScore})` };
  }
}

function getFailSafeDecision(strictMode = false) {
  if (strictMode) {
    return { decision: 'WARN', summary: 'Strict mode fallback' };
  }
  return { decision: 'ALLOW', summary: 'Fail-safe allowed' };
}

test('Decision Badge: BLOCK assigns red badge', () => {
  const badge = getDecisionBadge('BLOCK', 95);
  assert.equal(badge.text, 'ERR');
  assert.equal(badge.color, '#EF4444');
});

test('Decision Badge: WARN assigns amber badge', () => {
  const badge = getDecisionBadge('WARN', 60);
  assert.equal(badge.text, '!');
  assert.equal(badge.color, '#F59E0B');
});

test('Decision Badge: ALLOW assigns green badge', () => {
  const badge = getDecisionBadge('ALLOW', 15);
  assert.equal(badge.text, 'OK');
  assert.equal(badge.color, '#10B981');
});

test('Fail-Safe: Balanced mode fails open (ALLOW)', () => {
  const res = getFailSafeDecision(false);
  assert.equal(res.decision, 'ALLOW');
});

test('Fail-Safe: Strict mode fails closed (WARN)', () => {
  const res = getFailSafeDecision(true);
  assert.equal(res.decision, 'WARN');
});
