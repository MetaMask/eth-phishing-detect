/**
 * Legacy phishing detector configuration.
 *
 * @typedef {object} LegacyPhishingDetectorConfiguration
 * @property {string[]} [whitelist] - Origins that should not be blocked.
 * @property {string[]} [blacklist] - Origins to block.
 * @property {string[]} [fuzzylist] - Origins of common phishing targets.
 * @property {number} [tolerance] - Tolerance to use for the fuzzylist levenshtein match.
 */

/**
 * A configuration object for phishing detection.
 *
 * @typedef {object} PhishingDetectorConfiguration
 * @property {string[]} [allowlist] - Origins that should not be blocked.
 * @property {string[]} [blocklist] - Origins to block.
 * @property {string[]} [fuzzylist] - Origins of common phishing targets.
 * @property {string} name - The name of this configuration. Used to explain to users why a site is being blocked.
 * @property {number} [tolerance] - Tolerance to use for the fuzzylist levenshtein match.
 * @property {number} version - The current version of the configuration.
 */
