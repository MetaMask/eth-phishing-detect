export type Config = {
    version: number;
    tolerance: number;
    fuzzylist: string[];
    whitelist: string[];
    blacklist: string[];
}

export type InternalKey = 'blacklist' | 'whitelist' | 'fuzzylist';

export type ExternalKey = 'allowlist' | 'blocklist' | 'fuzzylist';
