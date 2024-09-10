#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { cleanAllowlist, cleanBlocklist } from '../src/clean-config.js';
import { Config } from '../src/types.js';
import { EXTERNAL_TO_INTERNAL_KEYS, isExternalKey } from '../src/constants.js';
import { serializeConfig } from '../src/utils.js';

const configPath = path.join(path.dirname(__dirname), 'src', 'config.json');

const main = (async () => {
  const key = process.argv[2];

  if (!isExternalKey(key)) {
    console.error(`Usage: ${process.argv.slice(0, 2).join(' ')} [allowlist|blocklist]`);
    console.error('Removes redundant entries from config section and writes filtered config in-place');
    return;
  }

  const config = JSON.parse(await readFile(configPath, { encoding: 'utf-8' })) as Config;

  let newConfig: Config;
  switch (key) {
    case 'allowlist':
      newConfig = cleanAllowlist(config);
      break;
    case 'blocklist':
      newConfig = cleanBlocklist(config);
      break;
    case 'fuzzylist':
      newConfig = config;
      break;
  }

  await writeFile(configPath, serializeConfig(newConfig));

  if (newConfig[EXTERNAL_TO_INTERNAL_KEYS[key]].length !== config[EXTERNAL_TO_INTERNAL_KEYS[key]].length) {
    console.log(`cleaned config ${key}: ${config[EXTERNAL_TO_INTERNAL_KEYS[key]].length} -> ${newConfig[EXTERNAL_TO_INTERNAL_KEYS[key]].length}`);
  }
});

main();
