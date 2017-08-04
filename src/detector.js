const levenshtein = require('fast-levenshtein')
const DEFAULT_TOLERANCE = 3

class PhishingDetector {

  constructor (opts) {
    this.whitelist = processDomainList(opts.whitelist || [])
    this.blacklist = processDomainList(opts.blacklist || [])
    this.fuzzylist = processDomainList(opts.fuzzylist || [])
    this.tolerance = ('tolerance' in opts) ? opts.tolerance : DEFAULT_TOLERANCE
  }

  check (domain) {
    const source = domainToParts(domain)

    // if source matches whitelist domain (or subdomain thereof), PASS
    const whitelistMatch = matchPartsAgainstList(source, this.whitelist)
    if (whitelistMatch) return { type: 'whitelist', result: false }

    // if source matches blacklist domain (or subdomain thereof), FAIL
    const blacklistMatch = matchPartsAgainstList(source, this.blacklist)
    if (blacklistMatch) return { type: 'blacklist', result: true }

    if (this.tolerance > 0) {
      // check if near-match of whitelist domain, FAIL
      let fuzzyForm = domainPartsToFuzzyForm(source)
      // strip www
      fuzzyForm = fuzzyForm.replace('www.', '')
      // check against fuzzylist
      const levenshteinMatched = this.fuzzylist.find((targetParts) => {
        const fuzzyTarget = domainPartsToFuzzyForm(targetParts)
        const distance = levenshtein.get(fuzzyForm, fuzzyTarget)
        return distance <= this.tolerance
      })
      if (levenshteinMatched) {
        const match = domainPartsToDomain(levenshteinMatched)
        return { type: 'fuzzy', result: true, match }
      }
    }

    // matched nothing, PASS
    return { type: 'all', result: false }
  }

}

module.exports = PhishingDetector

// util

function processDomainList (list) {
  return list.map(domainToParts)
}

function domainToParts (domain) {
  return domain.split('.').reverse()
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