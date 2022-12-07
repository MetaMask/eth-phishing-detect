#!/usr/bin/env node
const { spawnSync } = require('child_process');

console.warn(`*WARNING* blacklist.js/add:blacklist are deprecated and will be removed in a future version.
Use add-hosts.js/add:blocklist instead`);

const r = spawnSync('./src/add-hosts.js', ['./src/config.json', 'blocklist', ...process.argv.slice(2)]);
process.stderr.write(r.stderr.toString('utf-8'));
process.stdout.write(r.stdout.toString('utf-8'));
