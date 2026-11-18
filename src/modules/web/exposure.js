/**
 * web.exposure — files and pages that should never be public.
 *
 * Each candidate is a single GET of a well-known path. A finding needs a content signature, not
 * just a 200 status, so "soft 404" pages that answer 200 for everything cannot cause a false
 * positive. Secret values are never recorded: evidence previews are redacted by the evidence
 * store and observations name keys only.
 *
 * Pure helper `matchExposure(path, status, text)` is exported for tests.
 */

const REFS = Object.freeze({
  wstgFiles: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information',
  wstgDirListing: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/',
  git: 'https://owasp.org/www-community/attacks/Forced_browsing'
});

const SECRET_KEY = /(key|secret|token|pass|pwd|auth|credential|dsn|database_url|private)/i;

/** Path, signature and finding template. Order is the probe order. */
export const CANDIDATES = Object.freeze([
  { path: '/.git/HEAD', test: (t) => /^ref: refs\/|^[0-9a-f]{40}\s*$/m.test(t), severity: 'high', check: 'web.exposure.git',
    title: 'Git repository is downloadable (/.git/)', cwe: ['CWE-527'],
    description: 'The site serves its .git directory. Tools can rebuild the full source code and history from it.',
    impact: 'Source code, internal paths, and any secrets ever committed (including deleted ones) can be recovered.',
    remediation: 'Block access to /.git/ in the web server, remove the directory from the deployed site, and rotate any secret that was ever committed.' },
  { path: '/.env', test: (t) => /^\s*[A-Z][A-Z0-9_]{1,63}\s*=/m.test(t) && !/<html/i.test(t), severity: 'high', check: 'web.exposure.env',
    title: 'Environment file is public (/.env)', cwe: ['CWE-538'],
    description: 'The site serves a .env file, which usually holds configuration and credentials.',
    impact: 'Database passwords, API keys and signing secrets in this file are readable by anyone.',
    remediation: 'Remove the file from the web root, block dotfiles in the web server, and rotate every secret it contained.' },
  { path: '/server-status', test: (t) => /Apache Server Status/i.test(t), severity: 'medium', check: 'web.exposure.server-status',
    title: 'Apache server-status page is public', cwe: ['CWE-200'],
    description: 'mod_status is reachable from outside and lists live requests, client addresses and internal URLs.',
    impact: 'Leaks visitor IP addresses, internal paths and query strings, which can include tokens.',
    remediation: 'Restrict /server-status to localhost or an admin network with `Require local` or `Require ip`.' },
  { path: '/phpinfo.php', test: (t) => /<title>phpinfo\(\)<\/title>|PHP Version \d/i.test(t), severity: 'medium', check: 'web.exposure.phpinfo',
    title: 'phpinfo() page is public', cwe: ['CWE-200'],
    description: 'A phpinfo() page shows the full PHP configuration, loaded modules, paths and environment variables.',
    impact: 'Gives an attacker exact versions and configuration to target, and sometimes secrets from the environment.',
    remediation: 'Delete the file from the server.' },
  { path: '/.DS_Store', test: (t, b) => b?.subarray(4, 8).toString('latin1') === 'Bud1', severity: 'low', check: 'web.exposure.ds-store',
    title: 'macOS .DS_Store file is public', cwe: ['CWE-538'],
    description: 'A .DS_Store file lists the names of files in the directory, including ones that are not linked anywhere.',
    impact: 'Reveals hidden file and folder names, such as backups or admin pages.',
    remediation: 'Delete .DS_Store files from the deployment and block dotfiles in the web server.' }
]);

/**
 * Does this response prove the candidate is exposed?
 * @param {object} candidate one of CANDIDATES
 * @param {number} status HTTP status
 * @param {string} text body as text
 * @param {Buffer} [body] raw body for binary signatures
 */
export function matchExposure(candidate, status, text, body) {
  return status === 200 && Boolean(candidate.test(String(text ?? ''), body));
}

/** Directory listing on the web root itself. */
export function isDirectoryListing(text) {
  return /<title>Index of \//i.test(String(text ?? '')) || /<h1>Directory listing for \//i.test(String(text ?? ''));
}

/** Key names only, never values, for the .env observation. */
export function envKeyNames(text) {
  return [...String(text ?? '').matchAll(/^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=/gm)].map((m) => m[1]);
}

export default {
  id: 'web.exposure',
  phase: 'web',
  title: 'Exposed files',
  description: 'Looks for a public .git directory, .env file, server-status, phpinfo, .DS_Store and directory listing.',
  defaults: {},
  async run(ctx) {
    const probe = await ctx.openWebTarget();
    if (!probe) return { notes: ['no web target answered'] };
    if (ctx.options.mode === 'passive') return { notes: ['passive mode: path checks skipped'] };

    if (isDirectoryListing(probe.text)) {
      await ctx.addFinding({
        check: 'web.exposure.directory-listing', severity: 'low', confidence: 'confirmed', target: probe.url,
        title: 'Directory listing is enabled on the web root', observed: [{ key: 'page title', value: 'Index of /' }],
        evidence: [probe.session?.evidence?.id].filter(Boolean),
        description: 'The server lists the files in the directory instead of serving a page.',
        impact: 'Reveals file names, including backups and files that were never meant to be linked.',
        remediation: 'Disable autoindex (nginx) or `Options -Indexes` (Apache).',
        references: [REFS.wstgDirListing], cwe: ['CWE-548'], owasp: ['A05:2021']
      });
    }

    let checked = 0;
    for (const c of CANDIDATES) {
      if (ctx.signal.aborted) break;
      const url = ctx.helpers.joinUrl(probe.url, c.path);
      let res;
      try {
        res = await ctx.guard.fetch(url, { followRedirects: false, signal: ctx.signal });
      } catch (error) {
        if (error?.code === 'scope.denied' || error?.name === 'LimitError') throw error;
        ctx.logger.debug?.(`${c.path}: ${error.message}`);
        continue;
      }
      checked += 1;
      if (!matchExposure(c, res.status, res.text, res.response.body)) continue;
      const observed = c.check === 'web.exposure.env'
        ? [{ key: 'variables', value: envKeyNames(res.text).slice(0, 20).join(', ') || 'unknown' },
          { key: 'secret-looking keys', value: String(envKeyNames(res.text).filter((k) => SECRET_KEY.test(k)).length) }]
        : [{ key: 'status', value: String(res.status) }, { key: 'path', value: c.path }];
      await ctx.addFinding({
        check: c.check, severity: c.severity, confidence: 'confirmed', target: url, title: c.title,
        observed, evidence: [res.evidence.id], description: c.description, impact: c.impact, remediation: c.remediation,
        references: [c.check === 'web.exposure.git' ? REFS.git : REFS.wstgFiles], cwe: c.cwe, owasp: ['A05:2021']
      });
      await ctx.addAsset({ type: 'endpoint', value: url, state: 'tested' });
    }
    return { notes: [`checked ${checked} well-known paths`] };
  }
};
