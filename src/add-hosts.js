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
  const hosts = [...domains];

  const detector = new PhishingDetector({
    ...config,
    tolerance: section === 'blacklist' ? 0 : config.tolerance,
    [section]: domains,
  });

  let didFilter = false;

  for (const host of config[section]) {
    const r = detector.check(host);
    if (r.result) {
      console.error(`existing entry '${host}' removed due to now covered by '${r.match}' in '${r.type}'.`);
      didFilter = true;
      continue;
    }
    hosts.push(host);
  }

  const cfg = {
    ...config,
    [section]: hosts,
  };

  const output = JSON.stringify(cfg, null, 2) + '\n';

  writeFileSync(dest, output, (err) => {
    if (err) {
      return console.log(err);
    }
  });
  return didFilter;
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
        console.error(`'${host}' already covered by '${r.match}' in '${r.type}'.`);
        return false;
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


  try {
    /** @type {Set<string>} */
    const newHosts = new Set();
    // two-pass test for redundancy
    // 1. add hosts in-order...
    let detector = new PhishingDetector(config);
    for (const host of hosts) {
      if (validateHostRedundancy(detector, section, host)) {
        newHosts.add(host);
        detector.configs[0][section].push(PhishingDetector.domainToParts(host));
      }
    }
    // 2. ...and in reverse
    detector = new PhishingDetector(config);
    for (const host of hosts.reverse()) {
      if (newHosts.has(host)) {
        if (validateHostRedundancy(detector, section, host)) {
          detector.configs[0][section].push(PhishingDetector.domainToParts(host));
        } else {
          newHosts.delete(host);
        }
      }
    }

    // finally, generate new config with valid entries only added, and write result
    const didFilter = addHosts(config, SECTION_KEYS[section], Array.from(newHosts), destFile);

    // exit with non-success if filtering removed entries
    if (newHosts.size < hosts.length || didFilter) {
      process.exit(1);
    }
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}
