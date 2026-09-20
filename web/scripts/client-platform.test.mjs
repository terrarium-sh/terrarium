import assert from 'node:assert/strict';
import test from 'node:test';
import { detectClientPlatform } from '../src/lib/client-platform.ts';

test('selects desktop installers from client hints or browser identifiers', () => {
  for (const [platform, expected] of [['Windows', 'windows'], ['macOS', 'macos'], ['Linux', 'linux']]) {
    assert.equal(detectClientPlatform({ userAgent: '', userAgentData: { platform } }), expected);
  }
  for (const [userAgent, expected] of [
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'windows'],
    ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 'macos'],
    ['Mozilla/5.0 (X11; Linux x86_64)', 'linux'],
    ['Mozilla/5.0 (X11; Linux aarch64)', 'linux'],
  ]) {
    assert.equal(detectClientPlatform({ userAgent }), expected);
  }
  assert.equal(detectClientPlatform({ userAgent: 'Windows NT', userAgentData: { platform: 'Linux' } }), 'linux');
});

test('leaves mobile, ChromeOS, iPad desktop mode and unknown clients unselected', () => {
  for (const client of [
    { userAgent: 'Mozilla/5.0 (Linux; Android 15)' },
    { userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)' },
    { userAgent: 'Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X)' },
    { userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X)', platform: 'MacIntel', maxTouchPoints: 5 },
    { userAgent: 'Mozilla/5.0 (X11; CrOS x86_64)' },
    { userAgent: 'Linux', userAgentData: { mobile: true, platform: 'Linux' } },
    { userAgent: 'FreeBSD' },
    { userAgent: '' },
  ]) {
    assert.equal(detectClientPlatform(client), '', JSON.stringify(client));
  }
});
