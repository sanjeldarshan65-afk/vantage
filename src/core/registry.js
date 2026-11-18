import { promises as fs } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { VANTAGE_ROOT } from './paths.js';

const MODULES_DIR = path.join(VANTAGE_ROOT, 'src', 'modules');

/** Phase order is declared in defaults.js; the registry simply groups loaded modules. */
export class ModuleRegistry {
  constructor() {
    this.modules = new Map();
  }

  /** Register one module object (already imported). */
  register(module) {
    if (!module?.id) throw new Error('Module is missing an id.');
    if (!['recon', 'web'].includes(module.phase)) throw new Error(`Module ${module.id} has an invalid phase "${module.phase}".`);
    if (typeof module.run !== 'function') throw new Error(`Module ${module.id} is missing run(ctx).`);
    if (this.modules.has(module.id)) throw new Error(`Duplicate module id "${module.id}".`);
    this.modules.set(module.id, module);
    return this;
  }

  get(id) {
    return this.modules.get(id) ?? null;
  }

  all() {
    return [...this.modules.values()].sort((a, b) => a.id.localeCompare(b.id));
  }

  byPhase(phase) {
    return this.all().filter((module) => module.phase === phase);
  }

  get size() {
    return this.modules.size;
  }
}

/**
 * Discover module files by scanning `src/modules/<phase>/*.js` (sorted, deterministic order).
 * @param {{phases?: string[], dir?: string}} [options]
 * @returns {Promise<ModuleRegistry>}
 */
export async function loadModules({ phases = ['recon', 'web'], dir = MODULES_DIR } = {}) {
  const registry = new ModuleRegistry();
  for (const phase of phases) {
    const phaseDir = path.join(dir, phase);
    let entries = [];
    try {
      entries = await fs.readdir(phaseDir);
    } catch {
      continue;
    }
    for (const entry of entries.sort()) {
      if (!entry.endsWith('.js') || entry.startsWith('_')) continue;
      const file = path.join(phaseDir, entry);
      const imported = await import(pathToUrl(file));
      const module = imported.default ?? imported.module;
      if (module) registry.register(module);
    }
  }
  return registry;
}

function pathToUrl(file) {
  return pathToFileURL(path.resolve(file)).href;
}

/** Import one module by file path (used by tests). */
export async function importModule(file) {
  const imported = await import(pathToUrl(path.resolve(file)));
  return imported.default ?? imported.module;
}
