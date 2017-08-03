const test = require('tape')
const PhishingDetector = require('../src/detector')
const config = require('../src/config.json')

const detector = new PhishingDetector(config)


test('basic test', (t) => {

  // blacklist

  testDomain(t, {
    domain: 'metamask.com',
    type: 'blacklist',
    expected: true,
  })

  testDomain(t, {
    domain: 'myetherwaillet.com',
    type: 'blacklist',
    expected: true,
  })

  testDomain(t, {
    domain: 'myetherwaller.com',
    type: 'blacklist',
    expected: true,
  })

  testDomain(t, {
    domain: 'myetherweb.com.de',
    type: 'blacklist',
    expected: true,
  })

  testDomain(t, {
    domain: 'myeterwallet.com',
    type: 'blacklist',
    expected: true,
  })

  // whitelist

  testDomain(t, {
    domain: 'ledgerwallet.com',
    type: 'whitelist',
    expected: false,
  })

  // whitelist subdomains

  testDomain(t, {
    domain: 'www.metamask.io',
    type: 'whitelist',
    expected: false,
  })

  testDomain(t, {
    domain: 'faucet.metamask.io',
    type: 'whitelist',
    expected: false,
  })

  testDomain(t, {
    domain: 'zero.metamask.io',
    type: 'whitelist',
    expected: false,
  })

  testDomain(t, {
    domain: 'zero-faucet.metamask.io',
    type: 'whitelist',
    expected: false,
  })

  // fuzzy

  testDomain(t, {
    domain: 'metmask.io',
    type: 'fuzzy',
    expected: true,
  })

  testDomain(t, {
    domain: 'myetherwallet.cx',
    type: 'fuzzy',
    expected: true,
  })

  testDomain(t, {
    domain: 'myetherwallet.aaa',
    type: 'fuzzy',
    expected: true,
  })

  testDomain(t, {
    domain: 'myetherwallet.za',
    type: 'fuzzy',
    expected: true,
  })

  testDomain(t, {
    domain: 'myetherwallet.z',
    type: 'fuzzy',
    expected: true,
  })

  // no match

  testDomain(t, {
    domain: 'example.com',
    type: 'all',
    expected: false,
  })

  testDomain(t, {
    domain: 'etherscan.io',
    type: 'all',
    expected: false,
  })

  testDomain(t, {
    domain: 'ethereum.org',
    type: 'all',
    expected: false,
  })

  testDomain(t, {
    domain: 'etherid.org',
    type: 'all',
    expected: false,
  })

  testDomain(t, {
    domain: 'ether.cards',
    type: 'all',
    expected: false,
  })

  testDomain(t, {
    domain: 'easyeth.com',
    type: 'all',
    expected: false,
  })

  testDomain(t, {
    domain: 'etherdomain.com',
    type: 'all',
    expected: false,
  })

  testDomain(t, {
    domain: 'ethnews.com',
    type: 'all',
    expected: false,
  })

  testDomain(t, {
    domain: 'cryptocompare.com',
    type: 'all',
    expected: false,
  })

  testDomain(t, {
    domain: 'kraken.com',
    type: 'all',
    expected: false,
  })

  testDomain(t, {
    domain: 'myetherwallet.groovehq.com',
    type: 'all',
    expected: false,
  })

  t.end()
})

function testDomain(t, { domain, type, expected }) {
  const value = detector.check(domain)
  if (value.type === 'fuzzy') {
    t.comment(`"${domain}" fuzzy matches against "${value.match}"`)
  }
  t.equal(value.type, type, `type: "${domain}" should be "${type}"`)
  t.equal(value.result, expected, `result: "${domain}" should be match "${expected}"`)
}