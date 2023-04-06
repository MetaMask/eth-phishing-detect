#!/usr/bin/env node
const { writeFileSync } = require('fs');
const config = require('./config.json');
const PhishingDetector = require('./detector')

const SECTION_KEYS = {
  blocklist: 'blacklist',
  fuzzylist: 'fuzzylist',
  allowlist: 'whitelist',
};

const addHosts = (section, domains, dest) => {
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

const validateHostRedundancy = (detector, section, h) => {
  switch (section) {
    case 'blocklist': {
      const r = detector.check(h);
      if (r.result) {
        throw new Error(`'${h}' already covered by '${r.match}' in '${r.type}'.`);
      }
      return true;
    }
    case 'allowlist': {
      const r = detector.check(h);
      if (!r.result) {
        console.error(`'${h}' does not require allowlisting`);
        return false;
      }
      return true;
    }
    case 'fuzzylist': {
      if (config.fuzzylist.includes(h)) {
        console.error(`'${h}' already in fuzzylist`);
        return false;
      }
      return true;
    }
    default:
      throw new Error(`unrecognized section '${section}'`);
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
  if (process.argv.length < 4) {
    exitWithUsage(1);
  }

  const [destFile, section, ...hosts] = process.argv.slice(2);

  if (!Object.keys(SECTION_KEYS).includes(section) || hosts.length < 1) {
    exitWithUsage(1);
  }

  const detector = new PhishingDetector(config);
  let newHosts = [];

  try {
    newHosts = hosts.filter(h => validateHostRedundancy(detector, section, h));
  } catch (err) {
    console.error(err);
    process.exit(1);
  }

  addHosts(SECTION_KEYS[section], newHosts, destFile);
}
