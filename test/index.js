const fs = require("fs")
const test = require("tape")
const needle = require('needle')
const mapValues = require('async/mapValues')
const parseCsv = require("csv-parse/lib/sync")
const punycode = require('punycode')
const PhishingDetector = require("../src/detector")
const config = require("../src/config.json")
const alexaTopSites = require("./alexa.json")
const popularDapps = require("./dapps.json")

const detector = new PhishingDetector(config)
const metamaskGaq = loadMetamaskGaq()
let mewBlacklist, mewWhitelist
let ealBlacklist, ealWhitelist
const remoteBlacklistException = ['bittreat.com']

// load MEW blacklist
mapValues({
  mewBlacklist: 'https://raw.githubusercontent.com/MyEtherWallet/ethereum-lists/master/urls-darklist.json',
  mewWhitelist: 'https://raw.githubusercontent.com/MyEtherWallet/ethereum-lists/master/urls-lightlist.json',
  ealWhitelist: 'https://raw.githubusercontent.com/409H/EtherAddressLookup/master/whitelists/domains.json',
  ealBlacklist: 'https://raw.githubusercontent.com/409H/EtherAddressLookup/master/blacklists/domains.json',
}, (url, _, cb) => loadRemoteJson(url, cb), (err, results) => {
  if (err) throw err
  // parse results
  mewBlacklist = results.mewBlacklist.map(entry => entry.id).filter((domain) => !domain.includes('/')).map(punycode.toASCII)
  mewWhitelist = results.mewWhitelist.map(entry => entry.id).filter((domain) => !domain.includes('/')).map(punycode.toASCII)
  ealBlacklist = results.ealBlacklist.filter((domain) => !domain.includes('/')).map(punycode.toASCII)
  ealWhitelist = results.ealWhitelist.filter((domain) => !domain.includes('/')).map(punycode.toASCII)
  // remove exceptions
  mewBlacklist = mewBlacklist.filter((domain) => !domain.includes(remoteBlacklistException))
  ealBlacklist = ealBlacklist.filter((domain) => !domain.includes(remoteBlacklistException))
  startTests()
})

function loadMetamaskGaq () {
  // extract hits from Google Analytics data from metamask.io phishing warning
  // fetch from https://analytics.google.com/analytics/web/#my-reports/N6OapMZATf-zAzHjpa9Wcw/a37075177w102798190p106879314/%3F_u.dateOption%3Dlast7days%26454-table.plotKeys%3D%5B%5D%26454-table.rowStart%3D0%26454-table.rowCount%3D250/
  const rawCsv = fs.readFileSync(__dirname + '/metamaskGaq.csv', 'utf8')
  const result = parseCsv(rawCsv, {
    skip_empty_lines: true,
    comment: '#',
    columns: true,
  }).map(row => row.Source).map(punycode.toASCII)
  return result
}


function startTests () {

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

    // DO NOT detected as phishing

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
      "ethereum1.cz",
      "metalab.co",
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

  test("EAL lists", (t) => {
    testListIsPunycode(t, ealWhitelist)
    testListIsPunycode(t, ealBlacklist)
    testAnyType(t, false, ealWhitelist)
    testAnyType(t, true, ealBlacklist)
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

}

function testBlacklist (t, domains) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: "blacklist",
      expected: true,
    })
  })
}

function testWhitelist (t, domains) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: "whitelist",
      expected: false,
    })
  })
}

function testFuzzylist (t, domains) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: "fuzzy",
      expected: true,
    })
  })
}

function testListIsPunycode (t, list) {
  list.forEach((domain) => {
    t.equals(domain, punycode.toASCII(domain), `domain "${domain}" is encoded in punycode`)
  })
}

function testListDoesntContainRepeats (t, list) {
  list.forEach((domain) => {
    const count = list.filter(item => item === domain).length
    t.ok(count === 1, `domain "${domain}" appears in list only once`)
  })
}

function testNoMatch (t, domains) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      type: "all",
      expected: false,
    })
  })
}

function testAnyType (t, expected, domains) {
  domains.forEach((domain) => {
    testDomain(t, {
      domain: domain,
      expected,
    })
  })
}

function testDomain (t, { domain, type, expected }) {
  const value = detector.check(domain)
  // log fuzzy match for debugging
  // if (value.type === "fuzzy") {
  //   t.comment(`"${domain}" fuzzy matches against "${value.match}"`)
  // }
  // enforcing type is optional
  if (type) {
    t.equal(value.type, type, `type: "${domain}" should be "${type}"`)
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