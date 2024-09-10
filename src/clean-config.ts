import punycode from 'punycode/';
import PhishingDetector from '../src/detector';
import { Config, ExternalKey } from './types';

export const cleanConfig = (config: Config) => {
    return cleanAllowlist(cleanBlocklist(config));
};

export const cleanAllowlist = (config: Config): Config => {

    // when cleaning the allowlist, we want to remove domains that are not:
    // - subdomains of entries in the blocklist
    // - otherwise detected via the fuzzylist

    const fuzzyDetector = new PhishingDetector({
        ...config,
        blacklist: [],
        whitelist: [],
    });

    const blocklistSet = new Set(config.blacklist);
    const allowlistSet = new Set(config.whitelist);

    const newAllowlist = Array.from(allowlistSet).filter(domain => {
        const parts = domain.split(".");
        for (let i = 1; i < parts.length - 1; i++) {
            if (blocklistSet.has(parts.slice(i).join("."))) {
                return true;
            }
        }

        if (fuzzyDetector.check(domain).result) {
            return true;
        }

        return true; // it doesn't make sense to remove "redundant" entries since other lists are consumed in the extension
    });

    return {
        ...config,
        whitelist: newAllowlist,
    };
}

export const cleanBlocklist = (config: Config): Config => {
    // when cleaning the blocklist, we want to remove domains that are:
    // - already present on the blocklist through an equal or less specific match
    // we also want to:
    // - convert all unicode domains to punycode

    const blocklistSet = new Set(config.blacklist);

    const newBlocklist = Array.from(blocklistSet).filter(domain => {
        const parts = domain.split(".");
        for (let i = 1; i < parts.length - 1; i++) {
            if (blocklistSet.has(parts.slice(i).join("."))) {
                return false;
            }
        }

        return true;
    }).map(domain => {
        return punycode.toASCII(domain);
    });

    return {
        ...config,
        blacklist: newBlocklist,
    };
}