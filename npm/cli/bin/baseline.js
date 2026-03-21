#!/usr/bin/env node

const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const { installedBinaryPath, binaryFileName, resolveTarget } = require('../lib/release');

const packageRoot = path.resolve(__dirname, '..');
const target = resolveTarget(process.platform, process.arch);
const binaryPath = installedBinaryPath(packageRoot, target);

if (!fs.existsSync(binaryPath)) {
  const binaryName = binaryFileName(target);
  console.error(`[baseline-cli] Installed binary not found: ${binaryName}`);
  console.error('[baseline-cli] Reinstall the package with `npm i -g baseline-cli`.');
  process.exit(1);
}

const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: 'inherit',
  windowsHide: false
});

child.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 0);
});

child.on('error', (error) => {
  console.error(`[baseline-cli] Failed to start Baseline: ${error.message}`);
  process.exit(1);
});
