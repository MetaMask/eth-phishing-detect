#!/usr/bin/env node
const fs = require('fs');
const config = require('./config.json');

const LIST_KEYS = {
  blocklist: 'blacklist',
  fuzzylist: 'fuzzylist',
  allowlist: 'allowlist',
};

function addHosts(list, domains, dest) {
  config[list] = config[list].concat(domains);

  const output = JSON.stringify(config, null, 2) + '\n';

  fs.writeFile(dest, output, (err) => {
    if (err) {
      return console.log(err);
    }
  });
}

const exitWithUsage = (exitCode) => {
  console.error(`Usage: ${
    process.argv.slice(0,2).join(' ')
  } ${
    Object.keys(LIST_KEYS).join('|')
  } hostname...`);
  process.exit(exitCode);
};

if (process.argv.length < 4) {
  exitWithUsage(1);
}

const list = process.argv[2];
const hosts = process.argv.slice(3);

if (!Object.keys(LIST_KEYS).includes(list) || hosts.length < 1) {
  exitWithUsage(1);
}

addHosts(LIST_KEYS[list], hosts, './src/config.json');
