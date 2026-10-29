import { describe, expect, it } from 'vitest';
import { crackTime, strengthLabel } from './strength';

describe('crackTime', () => {
  it('speaks Russian with the right plural', () => {
    expect(crackTime(0.2)).toBe('мгновенно');
    expect(crackTime(45)).toBe('45 секунд');
    expect(crackTime(61)).toBe('1 минута');
    expect(crackTime(3 * 3600)).toBe('3 часа');
    expect(crackTime(5 * 86400)).toBe('5 дней');
    expect(crackTime(21 * 86400)).toBe('21 день');
    expect(crackTime(2 * 365 * 86400)).toBe('2 года');
    expect(crackTime(1e12)).toBe('века');
  });
});

describe('strengthLabel', () => {
  it('maps zxcvbn scores', () => {
    expect(strengthLabel(0)).toBe('очень слабый');
    expect(strengthLabel(2)).toBe('слабый');
    expect(strengthLabel(3)).toBe('хороший');
    expect(strengthLabel(4)).toBe('надёжный');
  });
});
