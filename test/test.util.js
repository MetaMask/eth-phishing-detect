const fs = require('fs')
const punycode = require('punycode/')
const needle = require('needle')
const parseCsv = require('csv-parse/sync')
const { cleanAllowlist, cleanBlocklist } = require('../src/clean-config.js')
const PhishingDetector = require('../src/detector.js')

function loadMetamaskGaq () {
  // extract hits from Google Analytics data from metamask.io phishing warning
  // fetch from https://analytics.google.com/analytics/web/#my-reports/N6OapMZATf-zAzHjpa9Wcw/a37075177w102798190p106879314/%3F_u.dateOption%3Dlast7days%26454-table.plotKeys%3D%5B%5D%26454-table.rowStart%3D0%26454-table.rowCount%3D250/
  const rawCsv = fs.readFileSync(__dirname + '/metamaskGaq.csv', 'utf8')
  const result = parseCsv.parse(rawCsv, {
    skip_empty_lines: true,
    comment: '#',
    columns: true,
  }).map(row => row.Source).map(punycode.toASCII)
  return result
}

function testBlocklist (t, domains, options) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: options && Array.isArray(options) ? 'blocklist' : 'blacklist',
      expected: true,
      options,
    })
  })
}

function testAllowlist (t, domains, options) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: options && Array.isArray(options) ? 'allowlist' : 'whitelist',
      expected: false,
      options,
    })
  })
}

function testFuzzylist (t, domains, options) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: 'fuzzy',
      expected: true,
      options,
    })
  })
}

function testListOnlyIncludesDomains (t, domains) {
  domains.forEach((domain) => {
    if (domain.includes('/')) {
      t.fail('should be valid domain, not path')
    }
    try {
      const url = new URL(`https://${domain}`)
      t.equal(url.hostname, domain, `parsed domain name should match hostname`)
    } catch (err) {
      t.fail(`should only be valid domain, saw '${domain}'\n:${err.message}`)
    }
  })
}

function testListIsPunycode (t, list) {
  list.forEach((domain) => {
    t.equals(domain, punycode.toASCII(domain), `domain '${domain}' is encoded in punycode`)
  })
}

function testListDoesntContainRepeats (t, list) {
  list.forEach((domain) => {
    const count = list.filter(item => item === domain).length
    t.ok(count === 1, `domain '${domain}' is duplicated. Domains can only appear in list once`)
  })
}

function testListIsContained (t, needles, stack) {
  needles.forEach((domain) => {
    if (!stack.includes(domain)) {
      t.fail(`${domain} in fuzzylist but not present in allowlist`, domain)
    }
  });
}

function testListNoBlocklistRedundancies (t, config) {
  const cleanConfig = cleanBlocklist(config)
  t.ok(cleanConfig.blacklist.length === config.blacklist.length, `blocklist contains ${config.blacklist.length-cleanConfig.blacklist.length} redundant entries. run 'yarn clean:blocklist'.`)
}

function testListNoAllowlistRedundancies (t, config) {
  const cleanConfig = cleanAllowlist(config)
  t.ok(cleanConfig.whitelist.length === config.whitelist.length, `allowlist contains ${config.whitelist.length-cleanConfig.whitelist.length} redundant entries. run 'yarn clean:allowlist'.`)
}

function testNoMatch (t, domains, options) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: 'all',
      expected: false,
      options,
    })
  })
}

function testAnyType (t, expected, domains, options) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      expected,
      options,
    })
  })
}

function testDomain (t, { domain, name, type, expected, options, version }) {
  const detector = new PhishingDetector(options)
  const value = detector.check(domain)
  // log fuzzy match for debugging
  // if (value.type === 'fuzzy') {
  //   t.comment(`"${domain}" fuzzy matches against "${value.match}"`)
  // }
  // enforcing type is optional
  if (type) {
    t.equal(value.type, type, `type: "${domain}" should be "${type}"`)
  }
  if (name) {
    t.equal(value.name, name, `name: "${domain}" should return result from config "${name}"`)
  }
  if (version) {
    t.equal(value.version, version, `version: "${domain}" should return result from config version '${version}'`)
  }
  // enforcing result is required
  t.equal(value.result, expected, `result: "${domain}" should be match "${expected}"`)
}

function loadRemoteJson (url, cb) {
  needle.get(url, (err, res) => {
    if (err) return cb(new Error(`Trouble loading list at "${url}":\n${err.stack}`))
    if (res.statusCode !== 200) {
      return cb(new Error(`Trouble loading list at "${url}":\n${res.body}`))
    }
    let _err, result
    try {
      result = JSON.parse(res.body)
    } catch (err) {
      _err = err
    }
    if (err) return cb(new Error(`Trouble loading list at "${url}":\n${err.stack}`))
    cb(_err, result)
  })
}

module.exports = {
  loadMetamaskGaq,
  loadRemoteJson,
  testAllowlist,
  testBlocklist,
  testDomain,
  testFuzzylist,
  testAnyType,
  testListDoesntContainRepeats,
  testListIsContained,
  testListIsPunycode,
  testListNoAllowlistRedundancies,
  testListNoBlocklistRedundancies,
  testListOnlyIncludesDomains,
  testNoMatch,
}
