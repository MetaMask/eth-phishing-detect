import { LegacyPhishingDetectorList } from "@metamask/phishing-controller";

export type Config = LegacyPhishingDetectorList & {
    version: number;
};

export type InternalKey = "blacklist" | "whitelist" | "fuzzylist";

export type ExternalKey = "allowlist" | "blocklist" | "fuzzylist";
