#!/usr/bin/env node
const addHosts = require('./add-hosts');

addHosts('blocklist', process.argv.slice(2), './src/config.json');
