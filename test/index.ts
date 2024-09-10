#!/usr/bin/env node

import { runTests as runConfigTests } from "./test-config.js";
import { runTests as runCleanConfigTests } from "./test-clean-config.js";
import { runTests as runListTests } from "./test-lists.js";

import config from "../src/config.json";

const SUITES = {
    config: [runConfigTests],
    cleanConfig: [runCleanConfigTests],
    lists: [runListTests],
};

const runTests = (target: string) => {
    const suites = target === 'all' ? Object.values(SUITES).flatMap(v => v) : SUITES[target];
    
    for (const suite of suites) {
        suite(config);
    }
}

const target = process.argv[2] || "all";
runTests(target);
