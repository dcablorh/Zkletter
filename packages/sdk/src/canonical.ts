// Canonical record encoding: JCS-style (RFC 8785) for string-valued maps.
// All values are strings (numbers are decimal strings, dates are ISO-8601).

export type Fields = Record<string, string>;

const KEY_RE = /^[a-z][a-z0-9_]{0,63}$/;

export function normalizeString(s: string): string {
  return s.normalize("NFC").trim().replace(/\s+/g, " ");
}

export function canonicalize(fields: Fields): string {
  const keys = Object.keys(fields);
  if (keys.length === 0) throw new Error("fields must not be empty");
  for (const k of keys) {
    if (!KEY_RE.test(k)) throw new Error(`invalid field name: ${k}`);
    if (typeof fields[k] !== "string") throw new Error(`field ${k} must be a string`);
  }
  // JCS sorts by UTF-16 code units; field names are ASCII so default sort matches.
  keys.sort();
  const body = keys.map((k) => `${JSON.stringify(k)}:${JSON.stringify(normalizeString(fields[k]))}`);
  return `{${body.join(",")}}`;
}
