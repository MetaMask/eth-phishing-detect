const test = require('tape')
const PhishingDetector = require('../src/detector')
const config = require('../src/config.json')
const alexaTopSites = require('./alexa.json')

const detector = new PhishingDetector(config)


test('basic test', (t) => {

  // blacklist

  testBlacklist(t, [
    'metamask.com',
    'myetherwaillet.com',
    'myetherwaller.com',
    'myetherweb.com.de',
    'myeterwallet.com',
    'xn--mytherwallet-fvb.com',
  ])

  // whitelist

  testWhitelist(t, [
    'ledgerwallet.com',
    'metamask.io',
    // whitelist subdomains
    'www.metamask.io',
    'faucet.metamask.io',
    'zero.metamask.io',
    'zero-faucet.metamask.io',
    'www.myetherwallet.com',
  ])

  // fuzzy

  testFuzzylist(t, [
    'metmask.io',
    'myetherwallet.cx',
    'myetherwallet.aaa',
    'myetherwallet.za',
    'myetherwallet.z',
  ])

  // no match

  testNoMatch(t, [
    'example.com',
    'etherscan.io',
    'ethereum.org',
    'etherid.org',
    'ether.cards',
    'easyeth.com',
    'etherdomain.com',
    'ethnews.com',
    'cryptocompare.com',
    'kraken.com',
    'myetherwallet.groovehq.com',
  ])

  t.end()
})

test('alexa top sites', (t) => {
  // alexa top sites
  testAnyType(t, false, alexaTopSites)
  t.end()
})


function testBlacklist(t, domains) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: 'blacklist',
      expected: true,
    })
  })
}

function testWhitelist(t, domains) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: 'whitelist',
      expected: false,
    })
  })
}

function testFuzzylist(t, domains) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: 'fuzzy',
      expected: true,
    })
  })
}

function testNoMatch(t, domains) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: 'all',
      expected: false,
    })
  })
}

function testAnyType(t, expected, domains) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      expected,
    })
  })
}

function testDomain(t, { domain, type, expected }) {
  const value = detector.check(domain)
  // log fuzzy match for debugging
  if (value.type === 'fuzzy') {
    t.comment(`"${domain}" fuzzy matches against "${value.match}"`)
  }
  // enforcing type is optional
  if (type) {
    t.equal(value.type, type, `type: "${domain}" should be "${type}"`)
  }
  // enforcing result is required
  t.equal(value.result, expected, `result: "${domain}" should be match "${expected}"`)
}