const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };
const COLORS = {
  debug: '\u001b[90m',
  info: '\u001b[36m',
  warn: '\u001b[33m',
  error: '\u001b[31m',
  scope: '\u001b[35m',
  reset: '\u001b[0m',
  dim: '\u001b[2m',
  bold: '\u001b[1m'
};

function useColor(stream) {
  return Boolean(stream?.isTTY) && !process.env.NO_COLOR && process.env.TERM !== 'dumb';
}

/**
 * Small leveled logger. Modules receive a child logger bound to their name.
 *
 * Sinks (`onRecord`) let the dashboard stream progress without the logger knowing about HTTP.
 */
export class Logger {
  /**
   * @param {{ level?: string, scope?: string, stream?: NodeJS.WritableStream, sink?: (record: object) => void }} [opts]
   */
  constructor(opts = {}) {
    this.level = opts.level ?? process.env.VANTAGE_LOG ?? 'info';
    this.scopeName = opts.scope ?? '';
    this.stream = opts.stream ?? process.stderr;
    this.sink = opts.sink ?? null;
    this.color = useColor(this.stream);
  }

  /** Create a logger sharing level/stream/sink but with a new scope prefix. */
  child(scope) {
    const next = new Logger({ level: this.level, scope: this.scopeName ? `${this.scopeName}:${scope}` : scope, stream: this.stream, sink: this.sink });
    next.color = this.color;
    return next;
  }

  setLevel(level) {
    this.level = level;
  }

  enabled(level) {
    return (LEVELS[level] ?? 99) >= (LEVELS[this.level] ?? 20);
  }

  /** Emit a record; also forwards it to the sink. */
  emit(level, message, data) {
    if (!this.enabled(level)) return;
    const record = { ts: new Date().toISOString(), level, scope: this.scopeName, message, data };
    this.sink?.(record);
    const tag = this.scopeName ? `[${this.scopeName}] ` : '';
    const color = this.color ? COLORS[level] ?? '' : '';
    const reset = this.color ? COLORS.reset : '';
    const suffix = data === undefined ? '' : ` ${this.color ? COLORS.dim : ''}${safeStringify(data)}${reset}`;
    this.stream.write(`${color}${level.padEnd(5)}${reset} ${tag}${message}${suffix}\n`);
  }

  debug(message, data) { this.emit('debug', message, data); }
  info(message, data) { this.emit('info', message, data); }
  warn(message, data) { this.emit('warn', message, data); }
  error(message, data) { this.emit('error', message, data); }

  /** A scope decision, logged distinctly so operators can audit live. */
  scope(message, data) { this.emit('scope', message, data); }
}

/** JSON.stringify that never throws (circular / BigInt safe). */
export function safeStringify(value, max = 400) {
  let text;
  try {
    text = JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v));
  } catch {
    text = String(value);
  }
  if (text === undefined) return '';
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/** A logger that discards everything; useful in tests. */
export function silentLogger() {
  return new Logger({ level: 'silent', stream: { write() {} } });
}
