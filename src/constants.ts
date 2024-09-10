import { ExternalKey, InternalKey } from "./types";

export const EXTERNAL_TO_INTERNAL_KEYS: Record<ExternalKey, InternalKey> = {
    allowlist: 'whitelist',
    blocklist: 'blacklist',
    fuzzylist: 'fuzzylist',
};

export const INTERNAL_TO_EXTERNAL_KEYS: Record<InternalKey, ExternalKey> = {
    whitelist: 'allowlist',
    blacklist: 'blocklist',
    fuzzylist: 'fuzzylist',
};

export const isExternalKey = (key: string): key is ExternalKey => {
    return Object.prototype.hasOwnProperty.call(EXTERNAL_TO_INTERNAL_KEYS, key);
}

export const isInternalKey = (key: string): key is InternalKey => {
    return Object.prototype.hasOwnProperty.call(INTERNAL_TO_EXTERNAL_KEYS, key);
}
