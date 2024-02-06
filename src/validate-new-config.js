#!/usr/bin/env node

const { readFileSync } = require('fs');
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
      const newHosts = new Set(newConfig[section].filter(h => !baseHosts.has(h)));
      if (new Set(newConfig[section]).size < newConfig[section].length) {
        const dupeHosts = new Set(
          newConfig[section].filter((host, i) =>
            newConfig[section].lastIndexOf(host) !== i
          )
        );

        return exitWithFail(`${listName} contains duplicate entries: ${Array.from(dupeHosts).join()}`);
      }

      // entry-wise checking is typically faster than doing a full consistency check
      const checkList = [...baseConfig[section]];
      for (const host of newHosts) {
        const cfg = {
          ...baseConfig,
          // FIXME: Temporary workaround during list inconsistency.
          // Can be reverted after 2023-05-14
          tolerance: listName === 'blocklist' ? 0 : 2,
          // tolerance: listName === 'blocklist' ? 0 : newConfig.tolerance,
          [section]: checkList,
        };
        const detector = new PhishingDetector(cfg);
        if (!validateHostRedundancy(detector, listName, host)) {
          return exitWithFail(`${listName} "${host}" failed redundancy check`);
        }
        checkList.push(host);
      }

      // 4. Check in reverse direction to catch existing entries which are now made redundant
      const cfg = {
        ...baseConfig,
        // FIXME: Temporary workaround during list inconsistency.
        // Can be reverted after 2023-05-14
        tolerance: listName === 'blocklist' ? 0 : 2,
        // tolerance: listName === 'blocklist' ? 0 : newConfig.tolerance,
        [section]: Array.from(newHosts),
      };
      const detector = new PhishingDetector(cfg);
      const allNewHosts = new Set(newConfig[section]);
      for (const host of baseHosts) {
        if (newHosts.has(host) || !allNewHosts.has(host)) {
          continue;
        }
        if (!validateHostRedundancy(detector, listName, host)) {
          return exitWithFail(`${listName} existing "${host}" failed redundancy check`);
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
