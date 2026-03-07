import { describe, it, expect } from 'vitest';
import { shellEscape } from './shell.js';

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
