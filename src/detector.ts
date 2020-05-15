const levenshtein = require('fast-levenshtein')
const DEFAULT_TOLERANCE = 3

interface checkReturnInterface {
  type: string;
  result: boolean;
  match?: string;
}

class PhishingDetector {
  whitelist: Array<string[]>;
  blacklist: Array<string[]>;
  fuzzylist: Array<string[]>;
  tolerance: Number;
  
  constructor (opts) {
    this.whitelist = processDomainList(opts.whitelist || [])
    this.blacklist = processDomainList(opts.blacklist || [])
    this.fuzzylist = processDomainList(opts.fuzzylist || [])
    this.tolerance = ('tolerance' in opts) ? opts.tolerance : DEFAULT_TOLERANCE
  }

  check (domain: string): checkReturnInterface {
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
      const levenshteinMatched: Array<string> = this.fuzzylist.find((targetParts) => {
        const fuzzyTarget: string = domainPartsToFuzzyForm(targetParts)
        const distance: Number = levenshtein.get(fuzzyForm, fuzzyTarget)
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

function processDomainList (list):Array<string[]> {
  return list.map(domainToParts)
}

function domainToParts (domain: string): Array<string> {
  return domain.split('.').reverse()
}

function domainPartsToDomain(domainParts: Array<string>): string {
  return domainParts.slice().reverse().join('.')
}

// for fuzzy search, drop TLD and re-stringify
function domainPartsToFuzzyForm(domainParts: Array<string>): string {
  return domainParts.slice(1).reverse().join('.')
}

// match the target parts, ignoring extra subdomains on source
//   source: [io, metamask, xyz]
//   target: [io, metamask]
//   result: PASS
function matchPartsAgainstList(source: Array<string>, list: Array<string[]>) {
  return list.some((target) => {
    // target domain has more parts than source, fail
    if (target.length > source.length) return false
    // source matches target or (is deeper subdomain)
    return target.every((part, index) => source[index] === part)
  })
}