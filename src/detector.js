const levenshtein = require('fast-levenshtein')
const DEFAULT_TOLERANCE = 3

class PhishingDetector {

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

  /**
   * Construct a phishing detector, which can check whether origins are known
   * to be malicious or similar to common phishing targets.
   *
   * A list of configurations is accepted. Each origin checked is processed
   * using each configuration in sequence, so the order defines which
   * configurations take precedence.
   *
   * @param {LegacyPhishingDetectorConfiguration | PhishingDetectorConfiguration[]} opts - Phishing detection options
   */
  constructor (opts) {
    // recommended configuration
    if (Array.isArray(opts)) {
      this.configs = processConfigs(opts)
      this.legacyConfig = false
    // legacy configuration
    } else {
      this.configs = [{
        allowlist: processDomainList(opts.whitelist || []),
        blocklist: processDomainList(opts.blacklist || []),
        fuzzylist: processDomainList(opts.fuzzylist || []),
        tolerance: ('tolerance' in opts) ? opts.tolerance : DEFAULT_TOLERANCE
      }]
      this.legacyConfig = true
    }
  }

  check(domain) {
    const result = this._check(domain)

    if (this.legacyConfig) {
      let legacyType = result.type;
      if (legacyType === 'allowlist') {
        legacyType = 'whitelist'
      } else if (legacyType === 'blocklist') {
        legacyType = 'blacklist'
      }
      return {
        match: result.match,
        result: result.result,
        type: legacyType,
      }
    }
    return result
  }

  _check (domain) {
    let fqdn = domain.substring(domain.length - 1) === "."
      ? domain.slice(0, -1)
      : domain;

    const source = domainToParts(fqdn)

    for (const { allowlist, name, version } of this.configs) {
      // if source matches whitelist domain (or subdomain thereof), PASS
      const whitelistMatch = matchPartsAgainstList(source, allowlist)
      if (whitelistMatch) return { name, result: false, type: 'allowlist', version }
    }

    for (const { blocklist, fuzzylist, name, tolerance, version } of this.configs) {
      // if source matches blacklist domain (or subdomain thereof), FAIL
      const blacklistMatch = matchPartsAgainstList(source, blocklist)
      if (blacklistMatch) return { name, result: true, type: 'blocklist', version }

      if (tolerance > 0) {
        // check if near-match of whitelist domain, FAIL
        let fuzzyForm = domainPartsToFuzzyForm(source)
        // strip www
        fuzzyForm = fuzzyForm.replace('www.', '')
        // check against fuzzylist
        const levenshteinMatched = fuzzylist.find((targetParts) => {
          const fuzzyTarget = domainPartsToFuzzyForm(targetParts)
          const distance = levenshtein.get(fuzzyForm, fuzzyTarget)
          return distance <= tolerance
        })
        if (levenshteinMatched) {
          const match = domainPartsToDomain(levenshteinMatched)
          return { name, match, result: true, type: 'fuzzy', version }
        }
      }
    }

    // matched nothing, PASS
    return { result: false, type: 'all' }
  }

}

module.exports = PhishingDetector

// util

function processConfigs(configs = []) {
  return configs.map((config) => {
    validateConfig(config)
    return Object.assign({}, config, {
      allowlist: processDomainList(config.allowlist || []),
      blocklist: processDomainList(config.blocklist || []),
      fuzzylist: processDomainList(config.fuzzylist || []),
      tolerance: ('tolerance' in config) ? config.tolerance : DEFAULT_TOLERANCE
    })
  });
}

function validateConfig(config) {
  if (config === null || typeof config !== 'object') {
    throw new Error('Invalid config')
  }

  if (config.tolerance && !config.fuzzylist) {
    throw new Error('Fuzzylist tolerance provided without fuzzylist')
  }

  if (
    typeof config.name !== 'string' ||
    config.name === ''
  ) {
    throw new Error("Invalid config parameter: 'name'")
  }

  if (
    !['number', 'string'].includes(typeof config.version) ||
    config.version === ''
  ) {
    throw new Error("Invalid config parameter: 'version'")
  }
}

function processDomainList (list) {
  return list.map(domainToParts)
}

function domainToParts (domain) {
  try {
  return domain.split('.').reverse()
  } catch (e) {
    throw new Error(JSON.stringify(domain))
  }
}

function domainPartsToDomain(domainParts) {
  return domainParts.slice().reverse().join('.')
}

// for fuzzy search, drop TLD and re-stringify
function domainPartsToFuzzyForm(domainParts) {
  return domainParts.slice(1).reverse().join('.')
}

// match the target parts, ignoring extra subdomains on source
//   source: [io, metamask, xyz]
//   target: [io, metamask]
//   result: PASS
function matchPartsAgainstList(source, list) {
  return list.some((target) => {
    // target domain has more parts than source, fail
    if (target.length > source.length) return false
    // source matches target or (is deeper subdomain)
    return target.every((part, index) => source[index] === part)
  })
}
