import { describe, expect, it } from 'vitest';
import { parseSettings } from './settings';

describe('parseSettings', () => {
  it('fills defaults, effects off when the system asks for reduced motion', () => {
    const s = parseSettings(null, true);
    expect(s).toMatchObject({ theme: 'phosphor', glow: false, vhs: false, pixels: false, blink: false, scale: 100, screenProtect: true });
    expect(parseSettings('{}', false)).toMatchObject({ glow: true, vhs: true, pixels: false, blink: true });
  });

  it('carries the old single "effects" switch over to the new ones', () => {
    expect(parseSettings('{"effects":false,"theme":"nord"}', false)).toMatchObject({ theme: 'nord', glow: false, vhs: false, blink: false });
    expect(parseSettings('{"effects":true}', true)).toMatchObject({ glow: true, vhs: true, blink: true });
    expect(parseSettings('{"effects":false,"glow":true}', false).glow).toBe(true);
  });

  it('survives garbage', () => {
    expect(parseSettings('not json', false).theme).toBe('phosphor');
    expect(parseSettings('[1,2]', false).autolockMin).toBe(10);
  });
});
