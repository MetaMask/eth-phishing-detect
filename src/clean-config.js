#!/usr/bin/env node
const { writeFileSync } = require('fs');
const path = require('path');
const PhishingDetector = require('./detector');

const SECTION_KEYS = {
  blocklist: 'blacklist',
  allowlist: 'whitelist',
};

/**
  * @param {PhishingDetectorConfiguration} config - Config to clean
  * @param {'blocklist'|'allowlist'} listName - List in config to clean
  * @returns {PhishingDetectorConfiguration} Cleaned config
  */
const cleanConfig = (config, listName) => {
  const section = SECTION_KEYS[listName];
  const newConfig = {
    version: config.version,
    tolerance: listName === 'blocklist' ? 0 : config.tolerance, // disable fuzzychecking for performance
    fuzzylist: [...config.fuzzylist],
    [SECTION_KEYS.allowlist] : [...config[SECTION_KEYS.allowlist]],
    [SECTION_KEYS.blocklist] : [...config[SECTION_KEYS.blocklist]],
  };

  const finalEntries = new Set();
  const excludedEntries = new Set();
  const detector = new PhishingDetector(newConfig);
  const baseList = detector.configs[0][listName];

  const isResultRedundant = listName === 'blocklist'
    ? r => r.result && r.type !== 'fuzzy'
    : r => !r.result;

  for (let i = 0; i < config[section].length; i++) {
    const host = config[section][i];

    // omit current domain from current list to see if results differ without
    detector.configs[0][listName] = baseList.slice(0,i).concat(baseList.slice(i+1));
    const result = detector.check(host);

    if (!isResultRedundant(result)) {
      finalEntries.add(host);
    } else {
      if (!excludedEntries.has(host)) {
        excludedEntries.add(host);
        if (listName === 'allowlist') {
          console.error(`removing redundant ${JSON.stringify({entry: host, result: result.result, tolerance: config.tolerance})}`);
        } else {
          console.error(`removing redundant ${JSON.stringify({entry: host, match: result.match, matchList: result.type})}`);
        }
      }
    }
  }

  // attempt to add back excluded entries ensuring consistency
  for (const host of excludedEntries) {
    newConfig[section] = Array.from(finalEntries);
    const detector = new PhishingDetector(newConfig);
    const result = detector.check(host);
    if (!isResultRedundant(result)) {
      console.error(`adding back ${JSON.stringify({host})}`);
      finalEntries.add(host);
    }
  }

  newConfig[section] = Array.from(finalEntries);
  newConfig.tolerance = config.tolerance;
  return newConfig;
};

const cleanAllowlist = config =>
  cleanConfig(config, 'allowlist');

const cleanBlocklist = config =>
  cleanConfig(config, 'blocklist');

module.exports = {
  cleanAllowlist,
  cleanBlocklist,
};

/////////////////////
//////// MAIN ///////
/////////////////////

if (require.main === module) {
  const exitWithUsage = (exitCode) => {
    console.error(`Usage: ${
      process.argv.slice(0,2).join(' ')
    } ${
      Object.keys(SECTION_KEYS).join('|')
    }`);
    console.error('Removes redundant entries from config section and writes filtered config to standard output');
    process.exit(exitCode);
  };

  const listName = process.argv[2];
  const section = SECTION_KEYS[listName];

  if (!section) {
    exitWithUsage(1);
  }

  try {
    /** @type {PhishingDetectorConfiguration} */
    const config = require('./config.json')
    const newConfig = cleanConfig(config, listName);

    // if this is piped to another process, then write to stdout.
    // otherwise, write new config to disk.
    const result = JSON.stringify(newConfig, undefined, 2)+'\n';
    if (process.stdout.isTTY) {
      const destinationPath = process.env['MM_OUTPUT_PATH'] || './config.json';
      writeFileSync(path.join(__dirname, destinationPath), result);
    } else {
      process.stdout.write(result);
    }

    if (newConfig[section].length !== config[section].length) {
      console.error(JSON.stringify({newCount: newConfig[section].length, oldCount: config[section].length}));
      process.exit(2);
    }
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}
