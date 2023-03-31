const fs = require("fs")
const test = require("tape")
const needle = require('needle')
const mapValues = require('async/mapValues')
const parseCsv = require('csv-parse/sync')
const punycode = require('punycode/')
const PhishingDetector = require('../src/detector.js')
const { cleanAllowlist, cleanBlocklist } = require('../src/clean-config.js')
const config = require("../src/config.json")
const alexaTopSites = require("./alexa.json")
const popularDapps = require("./dapps.json")

const metamaskGaq = loadMetamaskGaq()
let mewBlacklist, mewWhitelist
const remoteBlacklistException = ['bittreat.com']

// load MEW blacklist
mapValues({
  mewBlacklist: 'https://raw.githubusercontent.com/MyEtherWallet/ethereum-lists/master/src/urls/urls-darklist.json',
  mewWhitelist: 'https://raw.githubusercontent.com/MyEtherWallet/ethereum-lists/master/src/urls/urls-lightlist.json',
}, (url, _, cb) => loadRemoteJson(url, cb), (err, results) => {
  if (err) throw err
  // parse results
  mewBlacklist = results.mewBlacklist.map(entry => entry.id).filter((domain) => !domain.includes('/')).map(punycode.toASCII)
  mewWhitelist = results.mewWhitelist.map(entry => entry.id).filter((domain) => !domain.includes('/')).map(punycode.toASCII)
  // remove exceptions
  mewBlacklist = mewBlacklist.filter((domain) => !domain.includes(remoteBlacklistException))
  startTests()
})

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


function startTests () {

  test("legacy config", (t) => {

    // blacklist

    testBlacklist(t, [
      "metamask.com",
      "wallet-ethereum.net",
      "etherclassicwallet.com",
      "wallet-ethereum.net." //Test for absolute fully-qualified domain name
    ])

    // whitelist

    testWhitelist(t, [
      "metamask.io",
      "etherscan.io",
      // whitelist subdomains
      "www.metamask.io",
      "faucet.metamask.io",
      "zero.metamask.io",
      "zero-faucet.metamask.io",
      "www.myetherwallet.com",
    ])

    // fuzzy

    testFuzzylist(t, [
      "metmask.io",
      "myetherwallet.cx",
      "myetherwallet.aaa",
      "myetherwallet.za",
      "myetherwallet.z",
    ])

    // DO NOT detected as phishing

    testAnyType(t, false, [
      "example.com",
      "ethereum.org",
      "etherid.org",
      "ether.cards",
      "easyeth.com",
      "etherdomain.com",
      "ethnews.com",
      "cryptocompare.com",
      "kraken.com",
      "myetherwallet.groovehq.com",
      "dether.io",
      "ethermine.org",
      "slaask.com",
      "ethereumdev.io",
      "ethereumdev.kr",
      "etherplan.com",
      "etherplay.io",
      "ethtrade.org",
      "ethereumpool.co",
      "estream.to",
      "ethereum.os.tc",
      "theethereum.wiki",
      "taas.fund",
      "tether.to",
      "ether.direct",
      "themem.io",
      "metajack.im",
      "mestatalsl.biz",
      "thregg.com",
      "steem.io",
      "ethereum1.cz",
      "metalab.co",
      "originprotocol.com"
    ])

    // DO INDEED detect as phishing
    testAnyType(t, true, [
      "etherdelta-glthub.com",
      "omise-go.com",
      "omise-go.net",
      "numerai.tech",
      "decentraiand.org",
      "myetherwallet.com.ethpromonodes.com",
      "blockcrein.info",
      "blockchealn.info",
      "bllookchain.info",
      "blockcbhain.info",
      "tokenswap.org",
      "ethtrade.io",
      "myetherwallèt.com",
      "myetherwallet.cm",
      "myethervvallet.com",
      "metherwallet.com",
      "mtetherwallet.com",
      "my-etherwallet.com",
      "my-etherwallet.in",
      "myeherwallet.com",
      "myetcwallet.com",
      "myetehrwallet.com",
      "myeterwallet.com",
      "myethe.rwallet.com",
      "myethereallet.com",
      "myetherieumwallet.com",
      "myetherswallet.com",
      "myetherw.allet.com",
      "myetherwal.let.com",
      "myetherwalet.com",
      "myetherwaliet.com",
      "myetherwall.et.com",
      "myetherwaller.com",
      "myetherwallett.com",
      "myetherwaillet.com",
      "myetherwalllet.com",
      "myetherweb.com.de",
      "myethetwallet.com",
      "myethewallet.com",
      "myÄ—therwallet.com",
      "myelherwallel.com",
      "mvetherwallet.com",
      "myethewallet.net",
      "myetherwillet.com",
      "myetherwallel.com",
      "myeltherwallet.com",
      "myelherwallet.com",
      "wwwmyetherwallet.com",
      "myethermwallet.com",
      "myeth4rwallet.com",
      "myethterwallet.com",
      "origirprotocol.com"
    ])

    // etc...

    testNoMatch(t, [
      "MetaMask",
      "localhost",
      "bancor",
      "127.0.0.1",
    ])

    t.end()
  })

  test("current config", (t) => {

    // allow missing allowlist
    try {
      new PhishingDetector([
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
      ])
      t.pass('Passed validation')
    } catch (error) {
      t.fail(error.message)
    }

    // allow missing blocklist
    try {
      new PhishingDetector([
        {
          allowlist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
      ])
      t.pass('Passed validation')
    } catch (error) {
      t.fail(error.message)
    }

    // allow missing fuzzylist and tolerance
    try {
      new PhishingDetector([
        {
          allowlist: [],
          blocklist: [],
          name: 'first',
          version: 1
        },
      ])
      t.pass('Passed validation')
    } catch (error) {
      t.fail(error.message)
    }

    // allow missing tolerance
    try {
      new PhishingDetector([
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          version: 1
        },
      ])
      t.pass('Passed validation')
    } catch (error) {
      t.fail(error.message)
    }

    // throw when config is invalid
    const invalidConfigValues = [
      undefined,
      null,
      true,
      false,
      0,
      1,
      1.1,
      '',
      'test',
      () => {
        return {name: 'test', version: 1 }
      },
    ]
    for (const invalidValue of invalidConfigValues) {
      try {
        new PhishingDetector([invalidValue])
        t.fail('Did not fail validation')
      } catch (error) {
        t.equal(error.message, 'Invalid config')
      }
    }

    // throw when tolerance is provided without fuzzylist
    try {
      new PhishingDetector([
        {
          allowlist: [],
          blocklist: ['blocked-by-first.com'],
          name: 'first',
          tolerance: 2,
          version: 1,
        },
      ])
      t.fail('Did not fail validation')
    } catch (error) {
      t.equal(error.message, 'Fuzzylist tolerance provided without fuzzylist')
    }

    // throw when config name is invalid
    const invalidNameValues = [
      undefined,
      null,
      true,
      false,
      0,
      1,
      1.1,
      '',
      () => {
        return {name: 'test', version: 1 }
      },
      {}
    ]
    for (const invalidValue of invalidNameValues) {
      try {
        new PhishingDetector([
          {
            allowlist: [],
            blocklist: ['blocked-by-first.com'],
            fuzzylist: [],
            name: invalidValue,
            tolerance: 2,
            version: 1
          },
        ])
        t.fail('Did not fail validation')
      } catch (error) {
        t.equal(error.message, "Invalid config parameter: 'name'")
      }
    }

    // throw when config version is invalid
    const invalidVersionValues = [
      undefined,
      null,
      true,
      false,
      '',
      () => {
        return {name: 'test', version: 1 }
      },
      {}
    ]
    for (const invalidValue of invalidVersionValues) {
      try {
        new PhishingDetector([
          {
            allowlist: [],
            blocklist: ['blocked-by-first.com'],
            fuzzylist: [],
            name: 'first',
            tolerance: 2,
            version: invalidValue
          },
        ])
        t.fail('Did not fail validation')
      } catch (error) {
        t.equal(error.message, "Invalid config parameter: 'version'")
      }
    }

    const currentConfig = [{
      allowlist: config.whitelist,
      blocklist: config.blacklist,
      disputeUrl: 'https://github.com/MetaMask/eth-phishing-detect',
      fuzzylist: config.fuzzylist,
      name: 'MetaMask',
      tolerance: config.tolerance,
      version: config.version
    }]

    // return version with match
    testDomain(t, {
      domain: 'blocked-by-first.com',
      expected: true,
      version: 1,
      options: [
        {
          allowlist: [],
          blocklist: ['blocked-by-first.com'],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
      ],
    })

    // return name with match
    testDomain(t, {
      domain: 'blocked-by-first.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: ['blocked-by-first.com'],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
      ],
    })

    // blacklist

    testBlacklist(t, [
      "metamask.com",
      "wallet-ethereum.net",
      "etherclassicwallet.com",
      "wallet-ethereum.net." //Test for absolute fully-qualified domain name
    ], currentConfig)

    // whitelist

    testWhitelist(t, [
      "metamask.io",
      "etherscan.io",
      // whitelist subdomains
      "www.metamask.io",
      "faucet.metamask.io",
      "zero.metamask.io",
      "zero-faucet.metamask.io",
      "www.myetherwallet.com",
    ], currentConfig)

    // fuzzy

    testFuzzylist(t, [
      "metmask.io",
      "myetherwallet.cx",
      "myetherwallet.aaa",
      "myetherwallet.za",
      "myetherwallet.z",
    ], currentConfig)

    // DO NOT detected as phishing

    testAnyType(t, false, [
      "example.com",
      "ethereum.org",
      "etherid.org",
      "ether.cards",
      "easyeth.com",
      "etherdomain.com",
      "ethnews.com",
      "cryptocompare.com",
      "kraken.com",
      "myetherwallet.groovehq.com",
      "dether.io",
      "ethermine.org",
      "slaask.com",
      "ethereumdev.io",
      "ethereumdev.kr",
      "etherplan.com",
      "etherplay.io",
      "ethtrade.org",
      "ethereumpool.co",
      "estream.to",
      "ethereum.os.tc",
      "theethereum.wiki",
      "taas.fund",
      "tether.to",
      "ether.direct",
      "themem.io",
      "metajack.im",
      "mestatalsl.biz",
      "thregg.com",
      "steem.io",
      "ethereum1.cz",
      "metalab.co",
      "originprotocol.com"
    ], currentConfig)

    // DO INDEED detect as phishing
    testAnyType(t, true, [
      "etherdelta-glthub.com",
      "omise-go.com",
      "omise-go.net",
      "numerai.tech",
      "decentraiand.org",
      "myetherwallet.com.ethpromonodes.com",
      "blockcrein.info",
      "blockchealn.info",
      "bllookchain.info",
      "blockcbhain.info",
      "tokenswap.org",
      "ethtrade.io",
      "myetherwallèt.com",
      "myetherwallet.cm",
      "myethervvallet.com",
      "metherwallet.com",
      "mtetherwallet.com",
      "my-etherwallet.com",
      "my-etherwallet.in",
      "myeherwallet.com",
      "myetcwallet.com",
      "myetehrwallet.com",
      "myeterwallet.com",
      "myethe.rwallet.com",
      "myethereallet.com",
      "myetherieumwallet.com",
      "myetherswallet.com",
      "myetherw.allet.com",
      "myetherwal.let.com",
      "myetherwalet.com",
      "myetherwaliet.com",
      "myetherwall.et.com",
      "myetherwaller.com",
      "myetherwallett.com",
      "myetherwaillet.com",
      "myetherwalllet.com",
      "myetherweb.com.de",
      "myethetwallet.com",
      "myethewallet.com",
      "myÄ—therwallet.com",
      "myelherwallel.com",
      "mvetherwallet.com",
      "myethewallet.net",
      "myetherwillet.com",
      "myetherwallel.com",
      "myeltherwallet.com",
      "myelherwallet.com",
      "wwwmyetherwallet.com",
      "myethermwallet.com",
      "myeth4rwallet.com",
      "myethterwallet.com",
      "origirprotocol.com"
    ], currentConfig)

    // etc...

    testNoMatch(t, [
      "MetaMask",
      "localhost",
      "bancor",
      "127.0.0.1",
    ], currentConfig)

    t.end()
  })

  test("multiple configs", (t) => {

    // allow no config
    testDomain(t, {
      domain: 'default.com',
      expected: false,
      options: [],
      type: 'all'
    })

    // allow by default
    testDomain(t, {
      domain: 'default.com',
      expected: false,
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'all'
    })

    // block origin in first config
    testDomain(t, {
      domain: 'blocked-by-first.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: ['blocked-by-first.com'],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'blocklist'
    })

    // block origin in second config
    testDomain(t, {
      domain: 'blocked-by-second.com',
      expected: true,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: ['blocked-by-second.com'],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'blocklist'
    })

    // prefer first config when origin blocked by both
    testDomain(t, {
      domain: 'blocked-by-both.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: ['blocked-by-both.com'],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: ['blocked-by-both.com'],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'blocklist'
    })

    // test first fuzzylist
    testDomain(t, {
      domain: 'fuzzy-first.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-first.com'],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'fuzzy'
    })

    // test first fuzzylist at tolerance
    testDomain(t, {
      domain: 'fuzzy-firstab.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-first.com'],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'fuzzy'
    })

    // allow first fuzzylist beyond tolerance
    testDomain(t, {
      domain: 'fuzzy-firstabc.com',
      expected: false,
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-first.com'],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'all'
    })

    // test second fuzzylist
    testDomain(t, {
      domain: 'fuzzy-second.com',
      expected: true,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-second.com'],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'fuzzy'
    })

    // test second fuzzylist at tolerance
    testDomain(t, {
      domain: 'fuzzy-secondab.com',
      expected: true,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-second.com'],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'fuzzy'
    })

    // allow second fuzzylist past tolerance
    testDomain(t, {
      domain: 'fuzzy-secondabc.com',
      expected: false,
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-second.com'],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'all'
    })

    // prefer first config when blocked by both fuzzylists
    testDomain(t, {
      domain: 'fuzzy-both.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-both.com'],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-both.com'],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'fuzzy'
    })

    // prefer first config when blocked by first and fuzzy blocked by second
    testDomain(t, {
      domain: 'blocked-first-fuzzy-second.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: ['blocked-first-fuzzy-second.com'],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['blocked-first-fuzzy-second.com'],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'blocklist'
    })

    // prefer first config when fuzzy blocked by first and blocked by second
    testDomain(t, {
      domain: 'fuzzy-first-blocked-second.com',
      expected: true,
      name: 'first',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-first-blocked-second.com'],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: ['fuzzy-first-blocked-second.com'],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'fuzzy'
    })

    // allow origin that is allowed and not blocked on first config
    testDomain(t, {
      domain: 'allowed-first.com',
      expected: false,
      name: 'first',
      options: [
        {
          allowlist: ['allowed-first.com'],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin that is allowed and not blocked on second config
    testDomain(t, {
      domain: 'allowed-second.com',
      expected: false,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: ['allowed-second.com'],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin that is blocklisted and allowlisted, both on first config
    testDomain(t, {
      domain: 'allowed-and-blocked-first.com',
      expected: false,
      name: 'first',
      options: [
        {
          allowlist: ['allowed-and-blocked-first.com'],
          blocklist: ['allowed-and-blocked-first.com'],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin blocked by fuzzylist and allowlisted, both on first config
    testDomain(t, {
      domain: 'allowed-and-fuzzy-first.com',
      expected: false,
      name: 'first',
      options: [
        {
          allowlist: ['allowed-and-fuzzy-first.com'],
          blocklist: [],
          fuzzylist: ['allowed-and-fuzzy-first.com'],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin that is blocklisted and allowlisted, both on second config
    testDomain(t, {
      domain: 'allowed-and-blocked-second.com',
      expected: false,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: ['allowed-and-blocked-second.com'],
          blocklist: ['allowed-and-blocked-second.com'],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin blocked by fuzzylist and allowlisted, both on second config
    testDomain(t, {
      domain: 'allowed-and-fuzzy-second.com',
      expected: false,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: ['allowed-and-fuzzy-second.com'],
          blocklist: [],
          fuzzylist: ['allowed-and-fuzzy-second.com'],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin blocked by first config but allowedlisted by second
    testDomain(t, {
      domain: 'blocked-first-allowed-second.com',
      expected: false,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: ['blocked-first-allowed-second.com'],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: ['blocked-first-allowed-second.com'],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin allowed by first config but blocked by second
    testDomain(t, {
      domain: 'allowed-first-blocked-second.com',
      expected: false,
      name: 'first',
      options: [
        {
          allowlist: ['allowed-first-blocked-second.com'],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: ['allowed-first-blocked-second.com'],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin fuzzylist blocked by first config but allowed by second
    testDomain(t, {
      domain: 'fuzzy-first-allowed-second.com',
      expected: false,
      name: 'second',
      options: [
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['fuzzy-first-allowed-second.com'],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: ['fuzzy-first-allowed-second.com'],
          blocklist: [],
          fuzzylist: [],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    // allow origin allowed by first config but fuzzylist blocked by second
    testDomain(t, {
      domain: 'allowed-first-fuzzy-second.com',
      expected: false,
      name: 'first',
      options: [
        {
          allowlist: ['allowed-first-fuzzy-second.com'],
          blocklist: [],
          fuzzylist: [],
          name: 'first',
          tolerance: 2,
          version: 1
        },
        {
          allowlist: [],
          blocklist: [],
          fuzzylist: ['allowed-first-fuzzy-second.com'],
          name: 'second',
          tolerance: 2,
          version: 1
        },
      ],
      type: 'allowlist'
    })

    t.end()
  })

  test("alexa top sites", (t) => {
    testAnyType(t, false, alexaTopSites)
    t.end()
  })

  test("popular dapps", (t) => {
    testAnyType(t, false, popularDapps)
    t.end()
  })

  test("MEW lists", (t) => {
    testListIsPunycode(t, mewWhitelist)
    testListIsPunycode(t, mewBlacklist)
    testAnyType(t, false, mewWhitelist)
    testAnyType(t, true, mewBlacklist)
    t.end()
  })

  // make sure all metamask phishing hits are explicitly blacklisted
  test("metamask gaq", (t) => {
    testListIsPunycode(t, metamaskGaq)
    metamaskGaq.forEach((domain) => {
      const detector = new PhishingDetector(config)
      const value = detector.check(domain)
      // enforcing type is optional
      // if (value.type === 'all') {
      //   t.comment(`"${domain}" was NOT identified as phishing`)
      // }
      t.notEqual(value.type, 'fuzzy', `MetaMask Gaq result: "${domain}" should NOT be "fuzzy"`)
    })
    t.end()
  })

  test("config exclusively using punycode", (t) => {
    testListIsPunycode(t, config.whitelist)
    testListIsPunycode(t, config.fuzzylist)
    testListIsPunycode(t, config.blacklist)
    t.end()
  })

  test("config not repetitive", (t) => {
    testListDoesntContainRepeats(t, config.whitelist)
    testListDoesntContainRepeats(t, config.fuzzylist)
    testListDoesntContainRepeats(t, config.blacklist)
    t.end()
  })

  test("config only includes domains", (t) => {
    testListOnlyIncludesDomains(t, config.whitelist)
    testListOnlyIncludesDomains(t, config.fuzzylist)
    testListOnlyIncludesDomains(t, config.blacklist)
    t.end()
  })

  test("all fuzzylist entries are present in allowlist", (t) => {
    testListIsContained(t, config.fuzzylist, config.whitelist)
    t.end()
  })

  test("config does not contain redundant entries", (t) => {
    testListNoBlocklistRedundancies(t, config)
    testListNoAllowlistRedundancies(t, config)
    t.end()
  })
}

function testBlacklist (t, domains, options) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: options && Array.isArray(options) ? "blocklist" : "blacklist",
      expected: true,
      options,
    })
  })
}

function testWhitelist (t, domains, options) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: options && Array.isArray(options) ? "allowlist" : "whitelist",
      expected: false,
      options,
    })
  })
}

function testFuzzylist (t, domains, options) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: "fuzzy",
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
      t.fail(`should only be valid domain, saw "${domain}"\n:${err.message}`)
    }
  })
}

function testListIsPunycode (t, list) {
  list.forEach((domain) => {
    t.equals(domain, punycode.toASCII(domain), `domain "${domain}" is encoded in punycode`)
  })
}

function testListIsContained (t, needles, stack) {
  needles.forEach((domain) => {
    if (!stack.includes(domain)) {
      t.fail(`${domain} in fuzzylist but not present in allowlist`, domain)
    }
  });
}

function testListDoesntContainRepeats (t, list) {
  list.forEach((domain) => {
    const count = list.filter(item => item === domain).length
    t.ok(count === 1, `domain "${domain}" is duplicated. Domains can only appear in list once`)
  })
}

function testListNoBlocklistRedundancies (t, config) {
  const cleanConfig = cleanBlocklist(config)
  t.ok(cleanConfig.blacklist.length === config.blacklist.length, `blocklist contains ${config.blacklist.length-cleanConfig.blacklist.length} redundant entries. run "yarn clean:blocklist".`)
}

function testListNoAllowlistRedundancies (t, config) {
  const cleanConfig = cleanAllowlist(config)
  t.ok(cleanConfig.whitelist.length === config.whitelist.length, `allowlist contains ${config.whitelist.length-cleanConfig.whitelist.length} redundant entries. run "yarn clean:allowlist".`)
}

function testNoMatch (t, domains, options) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: "all",
      expected: false,
      options
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

function testDomain (t, { domain, name, type, expected, options = config, version }) {
  const detector = new PhishingDetector(options)
  const value = detector.check(domain)
  // log fuzzy match for debugging
  // if (value.type === "fuzzy") {
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
