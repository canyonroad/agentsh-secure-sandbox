import { describe, it, expect } from 'vitest';
import { shellEscape, envPrefix } from './shell.js';

describe('shellEscape', () => {
  it('joins simple command and args', () => {
    expect(shellEscape('ls', ['-la', '/workspace'])).toBe('ls -la /workspace');
  });

  it('quotes args with spaces', () => {
    expect(shellEscape('echo', ['hello world'])).toBe("echo 'hello world'");
  });

  it('escapes single quotes in args', () => {
    expect(shellEscape('echo', ["it's"])).toBe("echo 'it'\\''s'");
  });

  it('quotes args with shell metacharacters', () => {
    expect(shellEscape('echo', ['$HOME'])).toBe("echo '$HOME'");
    expect(shellEscape('echo', ['a;b'])).toBe("echo 'a;b'");
    expect(shellEscape('echo', ['a|b'])).toBe("echo 'a|b'");
  });

  it('handles empty args array', () => {
    expect(shellEscape('ls', [])).toBe('ls');
    expect(shellEscape('ls')).toBe('ls');
  });

  it('does not quote safe args', () => {
    expect(shellEscape('git', ['status', '--short'])).toBe('git status --short');
  });
});

describe('envPrefix', () => {
  it('returns empty string for undefined', () => {
    expect(envPrefix(undefined)).toBe('');
  });

  it('returns empty string for empty object', () => {
    expect(envPrefix({})).toBe('');
  });

  it('builds prefix with safe values unquoted', () => {
    expect(envPrefix({ TRACEPARENT: '00-abc-def-01' })).toBe(
      "TRACEPARENT=00-abc-def-01 ",
    );
  });

  it('handles multiple keys', () => {
    const result = envPrefix({ A: '1', B: '2' });
    expect(result).toBe("A=1 B=2 ");
  });

  it('skips keys with invalid characters', () => {
    expect(envPrefix({ 'VALID_KEY': 'ok', 'bad;key': 'evil', '123start': 'no' })).toBe(
      "VALID_KEY=ok ",
    );
  });

  it('skips keys that could inject shell syntax', () => {
    expect(envPrefix({ '$(whoami)': 'x' })).toBe('');
    expect(envPrefix({ 'A B': 'x' })).toBe('');
    expect(envPrefix({ 'A=B': 'x' })).toBe('');
  });

  it('quotes values with shell metacharacters', () => {
    expect(envPrefix({ FOO: 'hello world' })).toBe("FOO='hello world' ");
    expect(envPrefix({ FOO: "it's" })).toBe("FOO='it'\\''s' ");
  });
});
