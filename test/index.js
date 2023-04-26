#!/usr/bin/env node

const { runTests: runDetectorTests } = require('./detector.test.js');
const { runTests: runConfigTests } = require('./config.test.js');

const config = require('../src/config.json');

const SUITES = {
  config: [
    () => runConfigTests({config}),
  ],
  unit: [
    runDetectorTests,
  ],
}

function runTests (target = 'all') {
  const suites = target === 'all'
    ? [...Object.values(SUITES).flatMap(ss => [...ss])]
    : SUITES[target];
  for (const suite of suites) {
    suite();
  }
}

const target = process.argv[2] || 'all';
runTests(target);
