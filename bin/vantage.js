#!/usr/bin/env node
/**
 * VANTAGE CLI. Every network action goes through ScopeGuard; this file only wires things up.
 */
import { parseArgs } from 'node:util';
import { EngagementStore } from '../src/core/store.js';
import { ScopeGuard } from '../src/core/guard.js';
import { Engine } from '../src/core/engine.js';
import { loadModules } from '../src/core/registry.js';
import { createEngagementTemplate } from '../src/core/scope.js';
import { Logger } from '../src/core/log.js';
import { closeAgents } from '../src/core/http.js';
import { isValidEngagementId } from '../src/core/paths.js';
import { writeReports } from '../src/report/index.js';
import { createServer } from '../server/index.js';
import { startLab } from '../examples/lab-target.js';

const HELP = `VANTAGE — authorized security assessment workbench

Only assess systems you own or have written permission to test.

Usage:
  vantage init <id> --target <url|host|cidr> [--target ...] --auth-ref "<SOW / written approval>"
                    [--name ..] [--client ..] [--authorized-by ..] [--ends <ISO date>] [--mode passive|safe|full]
  vantage run <id> [--only <module,...>] [--phase recon|web] [--serve] [--port N]
  vantage report <id>
  vantage serve [--port N]
  vantage modules
  vantage demo [--serve] [--port N]   start a local misconfigured lab target and assess it

Data lives in ./data/engagements (override with VANTAGE_DATA_DIR).`;

const { values: opt, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    target: { type: 'string', multiple: true },
    'auth-ref': { type: 'string' },
    name: { type: 'string' },
    client: { type: 'string' },
    'authorized-by': { type: 'string' },
    ends: { type: 'string' },
    mode: { type: 'string' },
    only: { type: 'string' },
    phase: { type: 'string', multiple: true },
    serve: { type: 'boolean' },
    port: { type: 'string' },
    help: { type: 'boolean', short: 'h' }
  }
});

const logger = new Logger();
const [command, id] = positionals;
const port = opt.port ? Number(opt.port) : 7341;

function needId() {
  if (!isValidEngagementId(id)) fail('Give an engagement id: lowercase letters, digits, . _ - (e.g. acme-lab).');
}

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

async function serve(bus) {
  const dash = createServer({ logger, bus });
  const url = await dash.start(port);
  console.log(`\ndashboard  ${url}\ntoken      ${dash.token}   (needed only to change finding status)\n`);
  return dash;
}

async function init() {
  needId();
  if (!opt.target?.length) fail('init needs at least one --target.');
  if (!opt['auth-ref']) fail('init needs --auth-ref describing your written authorization.');
  const doc = createEngagementTemplate({
    id,
    name: opt.name,
    targets: opt.target,
    client: opt.client,
    authorizedBy: opt['authorized-by'],
    authorizationRef: opt['auth-ref'],
    endsAt: opt.ends,
    mode: opt.mode
  });
  const store = await EngagementStore.create(doc, { logger });
  console.log(`created engagement "${id}" in ${store.dir}\nscope: ${doc.scope.targets.join(', ')}`);
  await store.close();
}

/** Run every module against the engagement scope, then write reports. */
async function run(store, { dash = null } = {}) {
  const guard = new ScopeGuard({ engagement: store.engagement, scope: store.scope, logger, audit: store.audit, evidence: store.evidence });
  const engine = new Engine({ store, guard, logger, registry: await loadModules() });
  engine.on((event) => {
    dash?.bus.publish({ ...event, engagementId: store.id });
    if (event.type === 'finding') console.log(`  + [${event.finding.severity}] ${event.finding.title}`);
    if (event.type === 'module:done') console.log(`  ${event.module.id}: ${event.module.status} (${event.module.ms} ms)`);
  });
  const controller = new AbortController();
  process.once('SIGINT', () => controller.abort());
  const { run: result } = await engine.run({
    only: opt.only ? opt.only.split(',').map((s) => s.trim()) : null,
    phases: opt.phase?.length ? opt.phase : undefined,
    signal: controller.signal
  });
  const paths = await writeReports(store);
  const s = result.summary;
  console.log(`\nrun ${result.id} ${result.status}: ${result.stats.findings} new findings, ${result.stats.requests} requests, ${result.stats.denials} refused by scope`);
  console.log(`open findings by severity: ${Object.entries(s.bySeverity).map(([k, v]) => `${k} ${v}`).join(', ')}`);
  console.log(`report     ${paths.htmlPath}`);
  return result;
}

async function main() {
  if (opt.help || !command) return console.log(HELP);
  switch (command) {
    case 'init':
      return init();
    case 'run': {
      needId();
      const store = await EngagementStore.open(id, { logger });
      const dash = opt.serve ? await serve() : null;
      await run(store, { dash });
      await store.close();
      if (!dash) closeAgents();
      return;
    }
    case 'report': {
      needId();
      const store = await EngagementStore.open(id, { logger });
      console.log((await writeReports(store)).htmlPath);
      return store.close();
    }
    case 'serve':
      return serve();
    case 'modules':
      for (const m of (await loadModules()).all()) console.log(`${m.id.padEnd(20)} ${m.title}`);
      return;
    case 'demo': {
      const lab = await startLab();
      console.log(`lab target ${lab.url} (local, deliberately misconfigured)`);
      const doc = createEngagementTemplate({
        id: 'demo-lab',
        name: 'Demo lab',
        targets: [lab.url],
        client: 'Local lab',
        authorizedBy: 'operator (own machine)',
        authorizationRef: 'Local lab target started by `vantage demo`'
      });
      const store = await EngagementStore.create(doc, { logger, overwrite: true });
      const dash = opt.serve ? await serve() : null;
      await run(store, { dash });
      await store.close();
      if (!dash) {
        await lab.close();
        closeAgents();
      }
      return;
    }
    default:
      fail(`unknown command "${command}". Run vantage --help.`);
  }
}

main().catch((error) => fail(error?.message ?? String(error)));
