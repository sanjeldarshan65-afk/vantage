/** Base class for all VANTAGE errors; carries a stable machine-readable code. */
export class VantageError extends Error {
  /**
   * @param {string} code stable identifier, e.g. `scope.denied`
   * @param {string} message human readable
   * @param {object} [details]
   */
  constructor(code, message, details = {}) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    this.details = details;
  }
}

/** A target is outside the engagement scope (or explicitly excluded). */
export class ScopeError extends VantageError {
  constructor(message, details) {
    super('scope.denied', message, details);
  }
}

/** A budget / rate limit was exhausted. */
export class LimitError extends VantageError {
  constructor(message, details) {
    super('limit.exhausted', message, details);
  }
}

/** The engagement description or scope is invalid. */
export class ConfigError extends VantageError {
  constructor(message, details) {
    super('config.invalid', message, details);
  }
}

/** A required engagement / finding / run does not exist. */
export class NotFoundError extends VantageError {
  constructor(message, details) {
    super('not.found', message, details);
  }
}

/** A network operation failed. Expected; callers degrade gracefully. */
export class NetworkError extends VantageError {
  constructor(message, details) {
    super('network.failed', message, details);
  }
}
