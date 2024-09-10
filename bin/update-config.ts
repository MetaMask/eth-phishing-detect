#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { isExternalKey } from '../src/constants.js';
import { Config } from '../src/types.js';
import { addDomains, removeDomains } from '../src/update-config.js';
import { serializeConfig } from '../src/utils.js';

const configPath = path.join(path.dirname(__dirname), 'src', 'config.json');

const main = async () => {
  const [key, operation, ...hosts] = process.argv.slice(2);

  if (!isExternalKey(key) || (operation !== 'add' && operation !== 'remove') || hosts.length < 1) {
    console.error(`Usage: ${process.argv.slice(0, 2).join(' ')} [allowlist|blocklist|fuzzylist] [add|remove] [hostname...]`);
    console.error('Updates the config with the specified hosts');
    return;
  }

  const config = JSON.parse(await readFile(configPath, { encoding: 'utf-8' })) as Config;

  let newConfig: Config;
  switch (operation) {
    case 'add':
      newConfig = addDomains(config, key, hosts);
      break;
    case 'remove':
      newConfig = removeDomains(config, key, hosts);
      break;
  }

  await writeFile(configPath, serializeConfig(newConfig));
};

main();
