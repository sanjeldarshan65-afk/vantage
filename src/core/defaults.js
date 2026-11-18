/**
 * Engine defaults. Kept separate so tests and the CLI share one source of truth.
 */
export const DEFAULT_LIMITS = Object.freeze({
  requestsPerSecond: 5,
  perHostRequestsPerSecond: 3,
  concurrency: 4,
  maxRequests: 2000,
  timeoutMs: 8000,
  maxResponseBytes: 262144,
  maxEvidenceBytes: 4096
});

/** Phases run in this order; a phase only starts when the previous one finished. */
export const PHASES = Object.freeze(['recon', 'web']);

/** Default ports probed by `recon.ports` (top-100-ish, web-heavy). */
export const TOP_PORTS = Object.freeze([
  21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 500, 512, 513, 514,
  587, 623, 631, 636, 873, 902, 989, 990, 993, 995, 1080, 1099, 1433, 1521, 1723, 1883, 2049, 2082,
  2083, 2181, 2222, 2375, 2376, 2480, 3000, 3128, 3260, 3306, 3389, 4000, 4243, 4443, 4505, 4506,
  5000, 5432, 5555, 5601, 5672, 5900, 5901, 5984, 6000, 6379, 6443, 7001, 7070, 7443, 8000, 8008,
  8042, 8069, 8080, 8081, 8082, 8088, 8090, 8161, 8181, 8200, 8443, 8500, 8529, 8888, 9000, 9001,
  9042, 9090, 9092, 9100, 9200, 9300, 9418, 9443, 10000, 10250, 11211, 15672, 27017, 27018, 50070
]);

/** Common nameserver / service ports considered "web" for target selection. */
export const WEB_PORTS = Object.freeze([80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9443]);
