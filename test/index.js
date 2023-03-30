#!/usr/bin/env node

const { runTests: runDetectorTests } = require('./detector.test.js');
const { runTests: runConfigTests } = require('./config.test.js');

const config = require('../src/config.json');

function runTests () {
  runDetectorTests();
  runConfigTests({config});
}

runTests();
