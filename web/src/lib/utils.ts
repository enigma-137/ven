import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

export function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const diff = (then - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return "just now";
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
  if (abs < 86400 * 30) return rtf.format(Math.round(diff / 86400), "day");
  return new Date(iso).toLocaleDateString();
}

export function absoluteTime(iso: string): string {
  return new Date(iso).toLocaleString();
}

export async function copyText(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
}

/** Mirrors the Go serializer so "Copy KEY=value" produces valid dotenv. */
export function formatDotenvLine(key: string, value: string): string {
  if (value === "" || /^[A-Za-z0-9_\-./:@%+,=]+$/.test(value)) return `${key}=${value}`;
  if (!/['\n\r]/.test(value)) return `${key}='${value}'`;
  const escaped = value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\$/g, "\\$")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
  return `${key}="${escaped}"`;
}

export const KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_.]*$/;

const SECRET_SEGMENTS = new Set(
  ("SECRET SECRETS PASSWORD PASSWD PASS PWD TOKEN TOKENS KEY APIKEY CREDENTIAL CREDENTIALS CRED CREDS AUTH " +
    "PRIVATE SIGNATURE SIGNING SALT PEPPER DSN SESSION COOKIE JWT OTP PIN CERT CERTIFICATE PEM ACCESS WEBHOOK " +
    "HMAC ENCRYPTION CONNECTION CONNSTR").split(" "),
);
const TEXT_SEGMENTS = new Set(
  ("PORT HOST HOSTNAME ENV ENVIRONMENT MODE DEBUG LEVEL REGION ZONE TIMEOUT TTL ENABLED DISABLED ENABLE DISABLE " +
    "NAME VERSION LOCALE LANG TZ TIMEZONE COLOR THEME COUNT SIZE LIMIT MAX MIN PATH DIR FLAG FEATURE PUBLIC " +
    "ORIGIN DOMAIN WORKERS CONCURRENCY INTERVAL RETRIES FORMAT BUCKET").split(" "),
);
const CREDENTIAL_URL_PREFIXES = new Set(
  "DATABASE DB POSTGRES POSTGRESQL PG MYSQL MONGO MONGODB REDIS AMQP RABBITMQ KAFKA SMTP MAIL BROKER CACHE ELASTICSEARCH".split(" "),
);

/**
 * Client-side copy of the server's key-name heuristic, used only to
 * pre-select the toggle in the Add dialog. The server classifies imports.
 */
export function suggestType(key: string): "secret" | "text" {
  const upper = key.toUpperCase();
  const segs = upper.split(/[_.-]+/).filter(Boolean);
  if (segs.some((s) => SECRET_SEGMENTS.has(s))) return "secret";
  if (["PASSWORD", "SECRET", "TOKEN", "APIKEY", "PRIVATEKEY"].some((s) => upper.includes(s))) return "secret";
  const n = segs.length;
  if (n >= 2 && (segs[n - 1] === "URL" || segs[n - 1] === "URI")) {
    if (CREDENTIAL_URL_PREFIXES.has(segs[0]!) || (n > 2 && CREDENTIAL_URL_PREFIXES.has(segs[n - 2]!))) return "secret";
    return "text";
  }
  if (n > 1 && ["NODE", "NEXT", "VITE"].includes(segs[0]!) && segs[1] === "PUBLIC") return "text";
  if (segs.some((s) => TEXT_SEGMENTS.has(s))) return "text";
  return "secret";
}
