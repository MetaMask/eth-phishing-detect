const fs = require("fs")
const test = require("tape")
const parseCsv = require("csv-parse/lib/sync")
const PhishingDetector = require("../src/detector")
const config = require("../src/config.json")
const alexaTopSites = require("./alexa.json")
const popularDapps = require("./dapps.json")
const ealWhitelist = require("./ealWhitelist.json")
const ealBlacklist = require("./ealBlacklist.json")

// extract hits from Google Analytics data from metamask.io phishing warning
// fetch from https://analytics.google.com/analytics/web/#my-reports/N6OapMZATf-zAzHjpa9Wcw/a37075177w102798190p106879314/%3F_u.dateOption%3Dlast7days%26454-table.plotKeys%3D%5B%5D%26454-table.rowStart%3D0%26454-table.rowCount%3D250/
const rawCsv = fs.readFileSync(__dirname + '/metamaskGaq.csv', 'utf8')
const metamaskGaq = parseCsv(rawCsv, {
  skip_empty_lines: true,
  comment: '#',
  columns: true,
}).map(row => row.Source)


const detector = new PhishingDetector(config)


test("basic test", (t) => {

  // blacklist

  testBlacklist(t, [
    "metamask.com",
    "wallet-ethereum.net",
    "etherclassicwallet.com",
  ])

  // whitelist

  testWhitelist(t, [
    "ledgerwallet.com",
    "metamask.io",
    "etherscan.io",
    "ethereum.org",
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

  // do NOT detected as phishing

  testAnyType(t, false, [
    "example.com",
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
  ])

  // do detect as phishing
  testAnyType(t, true, [
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

test("alexa top sites", (t) => {
  testAnyType(t, false, alexaTopSites)
  t.end()
})

test("popular dapps", (t) => {
  testAnyType(t, false, popularDapps)
  t.end()
})

test("eal whitelist", (t) => {
  testAnyType(t, false, ealWhitelist)
  t.end()
})

test("eal blacklist", (t) => {
  testAnyType(t, true, ealBlacklist.filter((domain) => !domain.includes('/')))
  t.end()
})

// make sure all metamask phishing hits are explicitly blacklisted
test("metamask gaq", (t) => {
  metamaskGaq.forEach((domain) => {
    const value = detector.check(domain)
    // enforcing type is optional
    if (value.type === 'all') {
      t.comment(`"${domain}" was NOT identified as phishing`)
    }
    t.notEqual(value.type, 'fuzzy', `MetaMask Gaq result: "${domain}" should NOT be "fuzzy"`)
  })
  t.end()
})


function testBlacklist(t, domains) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: "blacklist",
      expected: true,
    })
  })
}

function testWhitelist(t, domains) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: "whitelist",
      expected: false,
    })
  })
}

function testFuzzylist(t, domains) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: "fuzzy",
      expected: true,
    })
  })
}

function testNoMatch(t, domains) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: "all",
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
  if (value.type === "fuzzy") {
    t.comment(`"${domain}" fuzzy matches against "${value.match}"`)
  }
  // enforcing type is optional
  if (type) {
    t.equal(value.type, type, `type: "${domain}" should be "${type}"`)
  }
  // enforcing result is required
  t.equal(value.result, expected, `result: "${domain}" should be match "${expected}"`)
}