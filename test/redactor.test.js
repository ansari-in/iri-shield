'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { redactPayload } = require('../src/redactor');

test('redacts configured sensitive fields recursively', () => {
  const result = redactPayload({
    user: {
      email: 'person@example.com',
      password: 'secret',
      profile: { token: 'abc.def.ghi' }
    }
  }, { fields: ['password', 'token', 'email'], mask: '[MASK]' });

  assert.equal(result.value.user.email, '[MASK]');
  assert.equal(result.value.user.password, '[MASK]');
  assert.equal(result.value.user.profile.token, '[MASK]');
  assert.equal(result.redactions, 3);
});

test('redacts sensitive strings in response text', () => {
  const result = redactPayload('contact admin@example.com with Bearer aaa.bbb.ccc', { fields: [], mask: '[X]' });
  assert.equal(result.value, 'contact [X] with [X]');
  assert.equal(result.redactions, 2);
});
