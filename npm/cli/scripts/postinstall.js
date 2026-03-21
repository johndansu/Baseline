#!/usr/bin/env node

const path = require('node:path');
const { installReleaseBinary } = require('../lib/install');

const packageRoot = path.resolve(__dirname, '..');

installReleaseBinary(packageRoot)
  .catch((error) => {
    console.error(`[baseline-cli] ${error.message}`);
    process.exit(1);
  });
