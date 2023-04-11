#!/usr/bin/env node
const { writeFileSync } = require('fs');
const PhishingDetector = require('./detector')

const SECTION_KEYS = {
  blocklist: 'blacklist',
  fuzzylist: 'fuzzylist',
  allowlist: 'whitelist',
};

/**
  * Adds new host to config and writes result to destination path on filesystem.
  * @param {PhishingDetectorConfiguration} config - Input config
  * @param {'blacklist'|'whitelist'} section - Target list of addition
  * @param {string[]} domains - domains to add
  * @param {string} dest - destination file path
  */
const addHosts = (config, section, domains, dest) => {
  const cfg = {
    ...config,
    [section]: config[section].concat(domains),
  };

  const output = JSON.stringify(cfg, null, 2) + '\n';

  writeFileSync(dest, output, (err) => {
    if (err) {
      return console.log(err);
    }
  });
}

/**
  * Adds new host to config and writes result to destination path on filesystem.
  * @param {PhishingDetector} detector - PhishingDetecor instance to utilize
  * @param {'blocklist'|'allowlist'} listName - Target list to validate
  * @param {string} host - hostname to validate
  * @returns {boolean}  true if valid as new entry; false otherwise
  */
const validateHostRedundancy = (detector, listName, host) => {
  switch (listName) {
    case 'blocklist': {
      const r = detector.check(host);
      if (r.result) {
        throw new Error(`'${host}' already covered by '${r.match}' in '${r.type}'.`);
      }
      return true;
    }
    case 'allowlist': {
      const r = detector.check(host);
      if (!r.result) {
        console.error(`'${host}' does not require allowlisting`);
        return false;
      }
      return true;
    }
    default:
      throw new Error(`unrecognized section '${listName}'`);
  }
}

module.exports = {
  addHosts,
  validateHostRedundancy,
};

/////////////////////
//////// MAIN ///////
/////////////////////

const exitWithUsage = (exitCode) => {
  console.error(`Usage: ${
    process.argv.slice(0,2).join(' ')
  } src/config.json ${
    Object.keys(SECTION_KEYS).join('|')
  } hostname...`);
  process.exit(exitCode);
};

if (require.main === module) {
  /** @type {PhishingDetectorConfiguration} */
  const config = require('./config.json');

  if (process.argv.length < 4) {
    exitWithUsage(1);
  }

  const [destFile, section, ...hosts] = process.argv.slice(2);

  if (!Object.keys(SECTION_KEYS).includes(section) || hosts.length < 1) {
    exitWithUsage(1);
  }

  const detector = new PhishingDetector(config);
  /** @type {string[]} */
  let newHosts = [];

  try {
    newHosts = hosts.filter(h => validateHostRedundancy(detector, section, h));
  } catch (err) {
    console.error(err);
    process.exit(1);
  }

  addHosts(config, SECTION_KEYS[section], newHosts, destFile);
}
