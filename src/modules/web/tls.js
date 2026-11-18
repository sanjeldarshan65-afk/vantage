/**
 * web.tls — transport security of the web target.
 *
 * Checks: plain-HTTP-only service, certificate trust / hostname / expiry / self-signed, and whether
 * the server still completes a TLS 1.0 or 1.1 handshake. The legacy-protocol probe can only
 * produce false negatives (when the local OpenSSL refuses to offer the old version), never false
 * positives, because a finding needs a completed handshake.
 *
 * Pure helpers `analyzeCertificate` and `analyzeLegacyProtocols` are exported for tests.
 */

const REFS = Object.freeze({
  owaspTls: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
  rfc8996: 'https://www.rfc-editor.org/rfc/rfc8996',
  mozillaTls: 'https://wiki.mozilla.org/Security/Server_Side_TLS'
});

const DAY = 864e5;

/**
 * Grade one leaf certificate.
 * @param {object|null} cert `response.tls.cert` from the guard
 * @param {{authorized?: boolean, authorizationError?: string|null, now?: number, target: string, evidence?: string|null}} ctx
 * @returns {object[]} finding partials
 */
export function analyzeCertificate(cert, { authorized = true, authorizationError = null, now = Date.now(), target, evidence = null }) {
  if (!cert) return [];
  const findings = [];
  const ev = evidence ? [evidence] : [];
  const base = { target, evidence: ev, cwe: ['CWE-295'], owasp: ['A02:2021'], references: [REFS.owaspTls] };
  const validTo = Date.parse(cert.validTo);
  const daysLeft = Number.isFinite(validTo) ? Math.floor((validTo - now) / DAY) : null;
  const observed = [
    { key: 'subject', value: String(cert.subject?.CN ?? JSON.stringify(cert.subject ?? '')) },
    { key: 'issuer', value: String(cert.issuer?.O ?? cert.issuer?.CN ?? JSON.stringify(cert.issuer ?? '')) },
    { key: 'valid to', value: String(cert.validTo ?? 'unknown') }
  ];

  if (daysLeft !== null && daysLeft < 0) {
    findings.push({ ...base, check: 'web.tls.cert-expired', severity: 'high', confidence: 'confirmed',
      title: `TLS certificate expired ${-daysLeft} day(s) ago`, observed,
      description: 'The certificate presented by the server is past its expiry date. Browsers show a full-page warning and many clients refuse to connect.',
      impact: 'Visitors are trained to click through certificate warnings, which removes their protection against interception.',
      remediation: 'Renew the certificate and automate renewal (for example with an ACME client) so it cannot lapse again.' });
  } else if (daysLeft !== null && daysLeft < 21) {
    findings.push({ ...base, check: 'web.tls.cert-expiring', severity: daysLeft < 7 ? 'medium' : 'low', confidence: 'confirmed',
      title: `TLS certificate expires in ${daysLeft} day(s)`, observed,
      description: 'The certificate is close to its expiry date.',
      impact: 'If renewal fails the site starts showing certificate errors.',
      remediation: 'Confirm automated renewal is working, or renew now.' });
  }
  if (cert.selfSigned) {
    findings.push({ ...base, check: 'web.tls.self-signed', severity: 'medium', confidence: 'confirmed',
      title: 'TLS certificate is self-signed', observed,
      description: 'The certificate is not issued by a publicly trusted certificate authority.',
      impact: 'Clients cannot tell this certificate apart from an attacker’s, so encryption gives no protection against interception.',
      remediation: 'Use a certificate from a public CA (Let’s Encrypt is free), or an internal CA that clients explicitly trust.' });
  }
  if (cert.hostnameMatch === false) {
    findings.push({ ...base, check: 'web.tls.hostname-mismatch', severity: 'high', confidence: 'confirmed',
      title: 'TLS certificate does not match the hostname', observed: [...observed, { key: 'subjectAltName', value: String(cert.subjectAltName ?? 'none') }],
      description: 'The names in the certificate do not cover the host that was requested.',
      impact: 'Browsers reject the connection; users who click through lose protection against interception.',
      remediation: 'Issue a certificate whose subjectAltName includes every hostname the site is served on.' });
  }
  if (!authorized && !cert.selfSigned && cert.hostnameMatch !== false && !(daysLeft !== null && daysLeft < 0)) {
    findings.push({ ...base, check: 'web.tls.untrusted', severity: 'medium', confidence: 'likely',
      title: 'TLS certificate chain is not trusted', observed: [...observed, { key: 'error', value: String(authorizationError ?? 'unknown') }],
      description: 'The certificate chain could not be validated against the system trust store. A missing intermediate certificate is the usual cause.',
      impact: 'Some clients will refuse to connect or show warnings.',
      remediation: 'Serve the full chain (leaf plus intermediates) and test with an external TLS checker.' });
  }
  if (cert.keyType === 'RSA' && Number(cert.keyBits) > 0 && Number(cert.keyBits) < 2048) {
    findings.push({ ...base, check: 'web.tls.weak-key', severity: 'medium', confidence: 'confirmed', cwe: ['CWE-326'],
      title: `TLS certificate uses a ${cert.keyBits}-bit RSA key`, observed,
      description: 'RSA keys shorter than 2048 bits are considered breakable.',
      impact: 'A well-resourced attacker could recover the private key.',
      remediation: 'Reissue the certificate with a 2048-bit (or larger) RSA key or an ECDSA P-256 key.' });
  }
  return findings;
}

/**
 * Turn legacy-protocol handshake results into findings.
 * @param {{version: string, open: boolean, evidenceId?: string|null}[]} results
 * @param {{target: string}} ctx
 */
export function analyzeLegacyProtocols(results, { target }) {
  const enabled = results.filter((r) => r.open);
  if (!enabled.length) return [];
  return [{
    check: 'web.tls.legacy-protocols', severity: 'medium', confidence: 'confirmed', target,
    title: `Server accepts ${enabled.map((r) => r.version).join(' and ')}`,
    observed: enabled.map((r) => ({ key: 'handshake', value: `${r.version} accepted` })),
    evidence: enabled.map((r) => r.evidenceId).filter(Boolean),
    description: 'TLS 1.0 and 1.1 were deprecated by RFC 8996 in 2021. Modern browsers no longer use them.',
    impact: 'Old protocol versions carry known weaknesses (for example BEAST and weak cipher suites) and are only useful to outdated or downgrade-attacked clients.',
    remediation: 'Disable TLS 1.0 and 1.1; offer TLS 1.2 and 1.3 only.',
    references: [REFS.rfc8996, REFS.mozillaTls], cwe: ['CWE-327'], owasp: ['A02:2021']
  }];
}

export default {
  id: 'web.tls',
  phase: 'web',
  title: 'TLS and certificates',
  description: 'Plain-HTTP service, certificate trust, hostname, expiry and key size, and TLS 1.0/1.1 support.',
  defaults: { timeoutMs: 5000 },
  async run(ctx) {
    const probe = await ctx.openWebTarget();
    if (!probe) return { notes: ['no web target answered'] };

    if (probe.scheme === 'http') {
      await ctx.addFinding({
        check: 'web.tls.no-https', severity: 'medium', confidence: 'confirmed', target: probe.url,
        title: 'Site is served over plain HTTP',
        observed: [{ key: 'scheme', value: 'http' }], evidence: [probe.session?.evidence?.id].filter(Boolean),
        description: 'The web target answered over unencrypted HTTP and no HTTPS endpoint was used.',
        impact: 'Anyone on the network path can read and modify traffic, including credentials and session cookies.',
        remediation: 'Serve the site over HTTPS, redirect HTTP to HTTPS, then enable HSTS.',
        references: [REFS.owaspTls], cwe: ['CWE-319'], owasp: ['A02:2021']
      });
      return { notes: ['target uses plain HTTP; certificate checks skipped'] };
    }

    const tls = probe.session?.response?.tls ?? null;
    const host = new URL(probe.url).hostname;
    for (const finding of analyzeCertificate(tls?.cert ?? null, {
      authorized: tls?.authorized !== false,
      authorizationError: tls?.authorizationError ?? null,
      target: probe.url,
      evidence: probe.session?.evidence?.id ?? null
    })) await ctx.addFinding(finding);

    if (ctx.options.mode === 'passive') return { notes: ['passive mode: legacy protocol handshakes skipped'] };
    const results = [];
    for (const version of ['TLSv1', 'TLSv1.1']) {
      try {
        const r = await ctx.guard.tlsProbe(host, probe.port, { minVersion: version, maxVersion: version, servername: host, timeoutMs: ctx.options.module.timeoutMs });
        results.push({ version: version === 'TLSv1' ? 'TLS 1.0' : 'TLS 1.1', open: Boolean(r.open && r.tls?.protocol === version), evidenceId: r.evidenceId });
      } catch (error) {
        ctx.logger.debug?.(`${version} probe failed: ${error.message}`);
      }
    }
    for (const finding of analyzeLegacyProtocols(results, { target: probe.url })) await ctx.addFinding(finding);
    await ctx.addAsset({ type: 'service', value: `${host}:${probe.port}`, attributes: { port: probe.port, protocol: 'tcp', tls: tls?.protocol ?? null }, state: 'tested' });
    return { notes: [`certificate checked; legacy handshakes ${results.filter((r) => r.open).length}/${results.length} accepted`] };
  }
};
