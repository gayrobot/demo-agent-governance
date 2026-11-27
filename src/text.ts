// Text helpers shared by the modules here. Lengths count Unicode code points, not
// UTF-16 units, so a limit means the same thing in every language the demos use
// (the helpdesk began in Python, where len() counts code points).

/** The number of Unicode code points in `text`. */
export function codePointLength(text: string): number {
  let n = 0;
  for (const _ of text) n++;
  return n;
}

/** `text` cut to at most `max` code points, never splitting a surrogate pair. */
export function clipCodePoints(text: string, max: number): string {
  if (!Number.isInteger(max) || max < 0) throw new RangeError("max must be a whole number");
  if (codePointLength(text) <= max) return text;
  return [...text].slice(0, max).join("");
}
