#!/usr/bin/env node
const { writeFileSync } = require('fs');
const path = require('path');
const PhishingDetector = require('./detector');
const punycode = require('punycode/');

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
  switch (listName) {
    case 'allowlist':
      return cleanAllowlist(config);
    case 'blocklist':
      return cleanBlocklist(config);
  }
};

const cleanAllowlist = config => {
  // when cleaning the allowlist, we want to remove domains that are not:
  // - subdomains of entries in the blocklist
  // - otherwise detected via the fuzzylist

  const fuzzyDetector = new PhishingDetector({
    ...config,
    [SECTION_KEYS['blocklist']]: [],
    [SECTION_KEYS['allowlist']]: [],
  });

  const blocklistSet = new Set(config[SECTION_KEYS['blocklist']]);
  const allowlistSet = new Set(config[SECTION_KEYS['allowlist']]);

  const newAllowlist = Array.from(allowlistSet).filter(domain => {
    const parts = domain.split(".");
    for (let i = 1; i < parts.length - 1; i++) {
      if (blocklistSet.has(parts.slice(i).join("."))) {
        return true;
      }
    }

    if (fuzzyDetector.check(domain).result) {
      return true;
    }

    console.log("cleaning redundant allowlist entry", domain);
  });

  return {
    ...config,
    [SECTION_KEYS['allowlist']]: newAllowlist,
  };
}

const cleanBlocklist = config => {
  // when cleaning the blocklist, we want to remove domains that are:
  // - already present on the blocklist through an equal or less specific match
  // we also want to:
  // - convert all unicode domains to punycode

  const blocklistSet = new Set(config[SECTION_KEYS['blocklist']]);

  const newBlocklist = Array.from(blocklistSet).filter(domain => {
    const parts = domain.split(".");
    for (let i = 1; i < parts.length - 1; i++) {
      if (blocklistSet.has(parts.slice(i).join("."))) {
        console.log("cleaning redundant blocklist entry", domain);
        return false;
      }
    }

    return true;
  }).map(domain => {
    return punycode.toASCII(domain);
  });

  return {
    ...config,
    [SECTION_KEYS['blocklist']]: newBlocklist,
  };
}

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
    if (process.stdout.isTTY || process.env['MM_OUTPUT_PATH']) {
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
