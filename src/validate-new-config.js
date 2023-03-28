#!/usr/bin/env node

const { readFileSync } = require('fs');
const deepEqual = require('deep-equal');
const PhishingDetector = require('../src/detector.js');
const { validateHostRedundancy } = require('../src/add-hosts.js');

const SECTION_KEYS = {
  blocklist: 'blacklist',
  allowlist: 'whitelist',
};

const exitWithUsage = (exitCode) => {
  console.error(`Usage: ${
    process.argv.slice(0,2).join(' ')
  } baseconfig.json newconfig.json`);
  console.error('Compares diff between base and new config, validating invariants');
  process.exit(exitCode);
};

const exitWithFail = (message) => {
  console.error(`[LIST ERROR]: ${message}`);
  process.exit(1);
};

if (process.argv.length !== 4) {
  exitWithUsage(1);
}

try {
  const [baseConfig, newConfig] = process.argv.slice(2).map(p => JSON.parse(readFileSync(p)));
  {
    // 1. Fuzzylist is remove-only
    let result;
    if (result = newConfig.fuzzylist.find(h => !baseConfig.fuzzylist.includes(h))) {
      exitWithFail(`unexpected fuzzylist entry "${result}"`);
    }
  }
  {
    // 2. Fuzzy-tolerance is strictly bounded to not grow
    if (!(newConfig.tolerance <= baseConfig.tolerance)) {
      exitWithFail(`new tolerance ${newConfig.tolerance} must be <= old tolerance ${oldConfig.tolerance}`);
    }
  }
  {
    // 3. New entries are not redundant
    ['blocklist','allowlist'].forEach(listName => {
      const section = SECTION_KEYS[listName];
      const baseHosts = new Set(baseConfig[section]);
      const newHosts = newConfig[section].filter(h => !baseHosts.has(h));

      // entry-wise checking is typically faster than doing a full consistency check
      const checkList = [...baseConfig[section]];
      for (const host of newHosts) {
        const cfg = {
          ...baseConfig,
          [section]: checkList,
        };
        const detector = new PhishingDetector(cfg);
        if (!validateHostRedundancy(detector, listName, host)) {
          exitWithFail(`${listName} "${host}" failed redundancy check`);
        }
      }
    });
  }
  // TODO: enable once lists are sorted in `config.json`
  /*
  {
    // 4. Entries are sorted alphabetically
    ['fuzzylist','blacklist','whitelist'].forEach(listName => {
      if(!deepEqual(newConfig[listName], [...newConfig[listName]].sort())) {
        exitWithFail(`${listName} not sorted`);
      }
    });
  }
  */
} catch (err) {
  exitWithFail(err.message || err);
}
