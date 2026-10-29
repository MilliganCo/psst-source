// Per-device preferences, kept in localStorage (nothing secret here).

export interface Settings {
  theme: string;
  /** Effects, each on its own switch. */
  glow: boolean;
  vhs: boolean;
  pixels: boolean;
  blink: boolean;
  /** Interface zoom, percent. */
  scale: number;
  density: 'compact' | 'normal' | 'comfy';
  autolockMin: number;
  lockOnMinimize: boolean;
  clipboardSec: number;
  /** Hide a revealed password after N seconds; 0 = keep it shown. */
  revealSec: number;
  /** Keep the window out of screenshots and screen sharing (Windows). */
  screenProtect: boolean;
  /** Closing the window keeps the app in the tray (Windows). */
  closeToTray: boolean;
  /** System notification for new chat messages (no message text in it). */
  chatNotify: boolean;
}

export function defaults(reducedMotion: boolean): Settings {
  return {
    theme: 'phosphor',
    glow: !reducedMotion,
    vhs: !reducedMotion,
    pixels: false,
    blink: !reducedMotion,
    scale: 100,
    density: 'normal',
    autolockMin: 10,
    lockOnMinimize: false,
    clipboardSec: 30,
    revealSec: 30,
    screenProtect: true,
    closeToTray: true,
    chatNotify: true,
  };
}

export function parseSettings(json: string | null, reducedMotion: boolean): Settings {
  let saved: Record<string, unknown> = {};
  try {
    const v = JSON.parse(json ?? '{}');
    if (v && typeof v === 'object' && !Array.isArray(v)) saved = v;
  } catch {
    /* defaults */
  }
  // Up to 0.3 one "effects" switch covered glow, scanlines and the blinking cursor.
  const { effects, ...rest } = saved;
  const legacy = typeof effects === 'boolean' ? { glow: effects, vhs: effects, blink: effects } : {};
  return { ...defaults(reducedMotion), ...legacy, ...rest } as Settings;
}
