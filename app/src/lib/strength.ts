// Editor feedback: zxcvbn score and guess time in words.

/** 1 минута, 3 минуты, 5 минут. */
function plural(n: number, [one, few, many]: [string, string, string]): string {
  const d = n % 10;
  const dd = n % 100;
  const w = d === 1 && dd !== 11 ? one : d >= 2 && d <= 4 && (dd < 12 || dd > 14) ? few : many;
  return `${n} ${w}`;
}

const UNITS: [number, [string, string, string]][] = [
  [365 * 86400, ['год', 'года', 'лет']],
  [30 * 86400, ['месяц', 'месяца', 'месяцев']],
  [86400, ['день', 'дня', 'дней']],
  [3600, ['час', 'часа', 'часов']],
  [60, ['минута', 'минуты', 'минут']],
  [1, ['секунда', 'секунды', 'секунд']],
];

export function crackTime(secs: number): string {
  if (secs < 1) return 'мгновенно';
  if (secs >= 100 * 365 * 86400) return 'века';
  const [size, words] = UNITS.find(([s]) => secs >= s)!;
  return plural(Math.floor(secs / size), words);
}

export const strengthLabel = (score: number) => ['очень слабый', 'очень слабый', 'слабый', 'хороший', 'надёжный'][score] ?? '';
