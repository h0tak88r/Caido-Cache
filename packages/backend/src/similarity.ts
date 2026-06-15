// Response-similarity helpers used to decide whether two HTTP response bodies
// represent "the same page". This mirrors the original Burp extension, which
// considered two bodies similar when the Jaro-Winkler distance was >= 0.8 OR
// the Levenshtein distance was <= 200. Both algorithms are O(n*m) in the
// worst case, so inputs are truncated and the Levenshtein computation is
// banded with an early cutoff to stay fast inside the QuickJS runtime.

const JARO_PREFIX_SCALE = 0.1;
const JARO_MAX_PREFIX = 4;
const JARO_INPUT_CAP = 4000;

export function jaroWinkler(a: string, b: string): number {
  const s1 = a.length > JARO_INPUT_CAP ? a.slice(0, JARO_INPUT_CAP) : a;
  const s2 = b.length > JARO_INPUT_CAP ? b.slice(0, JARO_INPUT_CAP) : b;

  if (s1 === s2) return 1;
  const len1 = s1.length;
  const len2 = s2.length;
  if (len1 === 0 || len2 === 0) return 0;

  const matchDistance = Math.max(0, Math.floor(Math.max(len1, len2) / 2) - 1);
  const s1Matches = new Array<boolean>(len1).fill(false);
  const s2Matches = new Array<boolean>(len2).fill(false);

  let matches = 0;
  for (let i = 0; i < len1; i++) {
    const start = Math.max(0, i - matchDistance);
    const end = Math.min(i + matchDistance + 1, len2);
    for (let j = start; j < end; j++) {
      if (s2Matches[j] === true) continue;
      if (s1[i] !== s2[j]) continue;
      s1Matches[i] = true;
      s2Matches[j] = true;
      matches++;
      break;
    }
  }

  if (matches === 0) return 0;

  let transpositions = 0;
  let k = 0;
  for (let i = 0; i < len1; i++) {
    if (s1Matches[i] !== true) continue;
    while (s2Matches[k] !== true) k++;
    if (s1[i] !== s2[k]) transpositions++;
    k++;
  }
  transpositions = Math.floor(transpositions / 2);

  const m = matches;
  const jaro = (m / len1 + m / len2 + (m - transpositions) / m) / 3;

  let prefix = 0;
  const maxPrefix = Math.min(JARO_MAX_PREFIX, len1, len2);
  while (prefix < maxPrefix && s1[prefix] === s2[prefix]) prefix++;

  return jaro + prefix * JARO_PREFIX_SCALE * (1 - jaro);
}

// Returns true when the Levenshtein edit distance between a and b is <= max.
// Uses a diagonal band of width `max` so the cost is O(n * max) rather than
// O(n * m). Distances larger than `max` are never needed, so the band is exact
// for every distance we care about.
export function levenshteinWithin(a: string, b: string, max: number): boolean {
  const n = a.length;
  const m = b.length;
  if (Math.abs(n - m) > max) return false;
  if (n === 0) return m <= max;
  if (m === 0) return n <= max;

  const inf = max + 1;
  let prev = new Array<number>(m + 1);
  for (let j = 0; j <= m; j++) prev[j] = j <= max ? j : inf;

  for (let i = 1; i <= n; i++) {
    const cur = new Array<number>(m + 1).fill(inf);
    cur[0] = i <= max ? i : inf;
    let rowMin = cur[0];
    const from = Math.max(1, i - max);
    const to = Math.min(m, i + max);
    for (let j = from; j <= to; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const del = (prev[j] ?? inf) + 1;
      const ins = (cur[j - 1] ?? inf) + 1;
      const sub = (prev[j - 1] ?? inf) + cost;
      const v = Math.min(del, ins, sub);
      cur[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return false;
    prev = cur;
  }

  return (prev[m] ?? inf) <= max;
}

export function similar(
  a: string,
  b: string,
  jaroThreshold: number,
  levenThreshold: number,
  maxLen: number,
): boolean {
  const x = a.length > maxLen ? a.slice(0, maxLen) : a;
  const y = b.length > maxLen ? b.slice(0, maxLen) : b;
  if (x === y) return true;
  if (levenshteinWithin(x, y, levenThreshold)) return true;
  return jaroWinkler(x, y) >= jaroThreshold;
}
