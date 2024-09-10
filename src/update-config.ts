import { cleanAllowlist, cleanBlocklist } from "./clean-config.js";
import { EXTERNAL_TO_INTERNAL_KEYS } from "./constants.js";
import { Config, ExternalKey } from "./types.js";

export const addDomains = (config: Config, key: ExternalKey, domains: string[]): Config => {
    if (key === 'fuzzylist') return config; // not allowed

    config[EXTERNAL_TO_INTERNAL_KEYS[key]].push(...domains);

    switch (key) {
        case 'allowlist':
            return cleanAllowlist(config);
        case 'blocklist':
            return cleanBlocklist(config);
    }
}

export const removeDomains = (config: Config, key: ExternalKey, domains: string[]): Config => {
    const toRemove = new Set(domains);

    config[EXTERNAL_TO_INTERNAL_KEYS[key]] = config[EXTERNAL_TO_INTERNAL_KEYS[key]].filter(domain => {
        return !toRemove.has(domain);
    });

    return config;
}