#!/usr/bin/env node
const { writeFileSync } = require('fs');
const PhishingDetector = require('./detector')

const SECTION_KEYS = {
  blocklist: 'blacklist',
  fuzzylist: 'fuzzylist',
  allowlist: 'whitelist',
};

const LISTNAME_KEYS = {
  blacklist: 'blocklist',
  whitelist: 'allowlist',
};

// We explicitly want these domains on the allowlist
// but redundancy check will fail if we don't ignore
const IGNORE_ALLOWLIST_CHECK = [
  "revoke.cash"
];

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
    // FIXME: Temporary workaround during list inconsistency.
    // Can be reverted after 2023-05-14
    tolerance: section === 'blacklist' ? 0 : 2,
    // tolerance: section === 'blacklist' ? 0 : config.tolerance,
    [section]: domains,
  });

  let didFilter = false;

  for (const host of config[section]) {
    if (!validateHostRedundancy(detector, LISTNAME_KEYS[section], host)) {
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

      const skipHostRedundancyCheck = new Set(IGNORE_ALLOWLIST_CHECK);
      if(skipHostRedundancyCheck.has(host)) {
        return true;
      }

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
    // sort entries by number of periods to correctly resolve internal redundancies
    hosts.sort((a,b) => (a.split('.').length - b.split('.').length) * 8 + a.localeCompare(b));

    // check each entry for redundancy, adding it to the detector's internal config if valid
    // reuse detector to avoid costly reinitialization
    let detector = new PhishingDetector(config);
    for (const host of hosts) {
      if (validateHostRedundancy(detector, section, host)) {
        newHosts.add(host);
        detector.configs[0][section].push(PhishingDetector.domainToParts(host));
      }
    }

    // generate new config with only valid entries added, and write result
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
