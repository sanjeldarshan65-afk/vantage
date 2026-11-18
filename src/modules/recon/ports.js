/**
 * recon.ports — TCP connect scan of in-scope hosts, limited to ports the scope allows.
 *
 * Only completes a TCP handshake and reads an optional banner; nothing is sent. Ports the scope
 * refuses (URL-origin targets pin one port, `scope.ports` can include/exclude) are skipped before
 * any packet leaves. Skipped in passive mode.
 *
 * Pure helper `classifyPort(port)` is exported for tests.
 */
import { TOP_PORTS } from '../../core/defaults.js';

/** Services that should almost never face the internet. */
export const RISKY = Object.freeze({
  21: ['FTP', 'medium', 'Credentials and data travel unencrypted.'],
  23: ['Telnet', 'high', 'Remote shell with unencrypted credentials.'],
  445: ['SMB', 'high', 'File sharing protocol with a long history of wormable bugs.'],
  1433: ['Microsoft SQL Server', 'high', 'Database directly reachable.'],
  2375: ['Docker API (no TLS)', 'critical', 'Unauthenticated Docker API gives full control of the host.'],
  3306: ['MySQL', 'high', 'Database directly reachable.'],
  3389: ['Remote Desktop', 'medium', 'Frequent target of password spraying and RDP exploits.'],
  5432: ['PostgreSQL', 'high', 'Database directly reachable.'],
  5900: ['VNC', 'high', 'Remote desktop that is often weakly protected.'],
  6379: ['Redis', 'high', 'Redis has no authentication by default.'],
  9200: ['Elasticsearch', 'high', 'Search cluster often exposed without authentication.'],
  11211: ['Memcached', 'high', 'No authentication; also abused for DDoS amplification.'],
  27017: ['MongoDB', 'high', 'Database directly reachable.']
});

/** @returns {{service: string, severity: string, why: string}|null} */
export function classifyPort(port) {
  const hit = RISKY[port];
  return hit ? { service: hit[0], severity: hit[1], why: hit[2] } : null;
}

export default {
  id: 'recon.ports',
  phase: 'recon',
  title: 'Open ports',
  description: 'TCP connect scan of the common ports the scope allows; flags databases, remote desktops and admin APIs.',
  defaults: { timeoutMs: 2500 },
  async run(ctx) {
    if (ctx.options.mode === 'passive') return { notes: ['passive mode: port scan skipped'] };
    const host = ctx.target?.host;
    if (!host) return { notes: ['no single host in scope to scan'] };
    const ports = [...new Set([...TOP_PORTS, ...(ctx.target.port ? [ctx.target.port] : [])])]
      .filter((port) => ctx.scope.matchHost(host, { port }).allowed);
    if (!ports.length) return { notes: ['scope allows no ports on this host'] };

    const open = [];
    await Promise.all(ports.map(async (port) => {
      if (ctx.signal.aborted) return;
      try {
        const r = await ctx.guard.tcpProbe(host, port, { timeoutMs: ctx.options.module.timeoutMs, signal: ctx.signal });
        if (r.open) open.push({ port, banner: r.banner, evidenceId: r.evidenceId });
      } catch (error) {
        if (error?.name === 'LimitError') throw error;
        ctx.logger.debug?.(`port ${port}: ${error.message}`);
      }
    }));
    open.sort((a, b) => a.port - b.port);

    for (const { port, banner, evidenceId } of open) {
      await ctx.addAsset({ type: 'service', value: `${host}:${port}`, attributes: { port, protocol: 'tcp', banner: banner ? banner.slice(0, 80) : null }, state: 'tested' });
      const risky = classifyPort(port);
      if (!risky) continue;
      await ctx.addFinding({
        check: `recon.ports.exposed-${risky.service.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-$/, '')}`,
        severity: risky.severity, confidence: 'likely', target: `${host}:${port}`,
        title: `${risky.service} port ${port} is reachable`,
        observed: [{ key: 'port', value: `${port}/tcp open` }, ...(banner ? [{ key: 'banner', value: banner.slice(0, 120) }] : [])],
        evidence: [evidenceId].filter(Boolean),
        description: `TCP port ${port}, normally used by ${risky.service}, accepted a connection. ${risky.why}`,
        impact: 'Services like this should sit behind a VPN or firewall; exposing them invites brute force and exploitation.',
        remediation: `Restrict port ${port} to trusted networks with a firewall rule, or bind the service to localhost.`,
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html'],
        cwe: ['CWE-668'], owasp: ['A05:2021']
      });
    }
    return { notes: [`${open.length} of ${ports.length} allowed ports open`] };
  }
};
