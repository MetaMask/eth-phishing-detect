const mapValues = require('async/mapValues')
const punycode = require('punycode/')
const test = require('tape')

const PhishingDetector = require('../src/detector.js')

const {
  testAllowlist,
  testBlocklist,
  testFuzzylist,
  loadMetamaskGaq,
  loadRemoteJson,
  testAnyType,
  testListDoesntContainRepeats,
  testListIsContained,
  testListIsPunycode,
  testListNoAllowlistRedundancies,
  testListNoBlocklistRedundancies,
  testListOnlyIncludesDomains,
  testNoMatch,
} = require('./test.util.js')
const alexaTopSites = require('./alexa.json')
const popularDapps = require('./dapps.json')

const metamaskGaq = loadMetamaskGaq()
let mewBlacklist, mewWhitelist

const remoteBlacklistException = ['bittreat.com']

function runTests ({ config }) {
  // load MEW blocklist
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
    startTests({ config })
  })
}


function startTests ({ config }) {

  test('legacy config', (t) => {
    // blocklist

    testBlocklist(t, [
      'metamask.com',
      'wallet-ethereum.net',
      'etherclassicwallet.com',
      'wallet-ethereum.net.' //Test for absolute fully-qualified domain name
    ], config)

    // allowlist

    testAllowlist(t, [
      'metamask.io',
      'etherscan.io',
      // allowlist subdomains
      'www.metamask.io',
      'faucet.metamask.io',
      'zero.metamask.io',
      'zero-faucet.metamask.io',
      'www.myetherwallet.com',
    ], config)

    // fuzzy

    testFuzzylist(t, [
      'metmask.io',
      'myetherwallet.cx',
      'myetherwallet.aaa',
      'myetherwallet.za',
      'myetherwallet.z',
    ], config)

    // DO NOT detected as phishing

    testAnyType(t, false, [
      'example.com',
      'ethereum.org',
      'etherid.org',
      'ether.cards',
      'easyeth.com',
      'etherdomain.com',
      'ethnews.com',
      'cryptocompare.com',
      'kraken.com',
      'myetherwallet.groovehq.com',
      'dether.io',
      'ethermine.org',
      'slaask.com',
      'ethereumdev.io',
      'ethereumdev.kr',
      'etherplan.com',
      'etherplay.io',
      'ethtrade.org',
      'ethereumpool.co',
      'estream.to',
      'ethereum.os.tc',
      'theethereum.wiki',
      'taas.fund',
      'tether.to',
      'ether.direct',
      'themem.io',
      'metajack.im',
      'mestatalsl.biz',
      'thregg.com',
      'steem.io',
      'ethereum1.cz',
      'metalab.co',
      'originprotocol.com'
    ], config)

    // DO INDEED detect as phishing
    testAnyType(t, true, [
      'etherdelta-glthub.com',
      'omise-go.com',
      'omise-go.net',
      'numerai.tech',
      'decentraiand.org',
      'myetherwallet.com.ethpromonodes.com',
      'blockcrein.info',
      'blockchealn.info',
      'bllookchain.info',
      'blockcbhain.info',
      'tokenswap.org',
      'ethtrade.io',
      'myetherwallèt.com',
      'myetherwallet.cm',
      'myethervvallet.com',
      'metherwallet.com',
      'mtetherwallet.com',
      'my-etherwallet.com',
      'my-etherwallet.in',
      'myeherwallet.com',
      'myetcwallet.com',
      'myetehrwallet.com',
      'myeterwallet.com',
      'myethe.rwallet.com',
      'myethereallet.com',
      'myetherieumwallet.com',
      'myetherswallet.com',
      'myetherw.allet.com',
      'myetherwal.let.com',
      'myetherwalet.com',
      'myetherwaliet.com',
      'myetherwall.et.com',
      'myetherwaller.com',
      'myetherwallett.com',
      'myetherwaillet.com',
      'myetherwalllet.com',
      'myetherweb.com.de',
      'myethetwallet.com',
      'myethewallet.com',
      'myÄ—therwallet.com',
      'myelherwallel.com',
      'mvetherwallet.com',
      'myethewallet.net',
      'myetherwillet.com',
      'myetherwallel.com',
      'myeltherwallet.com',
      'myelherwallet.com',
      'wwwmyetherwallet.com',
      'myethermwallet.com',
      'myeth4rwallet.com',
      'myethterwallet.com',
      'origirprotocol.com'
    ], config)

    // etc...

    testNoMatch(t, [
      'MetaMask',
      'localhost',
      'bancor',
      '127.0.0.1',
    ], config)

    t.end()
  })

  test('current config', (t) => {
    const currentConfig = [{
      allowlist: config.whitelist,
      blocklist: config.blacklist,
      disputeUrl: 'https://github.com/MetaMask/eth-phishing-detect',
      fuzzylist: config.fuzzylist,
      name: 'MetaMask',
      tolerance: config.tolerance,
      version: config.version
    }]

    // blocklist

    testBlocklist(t, [
      'metamask.com',
      'wallet-ethereum.net',
      'etherclassicwallet.com',
      'wallet-ethereum.net.' //Test for absolute fully-qualified domain name
    ], currentConfig)

    // allowlist

    testAllowlist(t, [
      'metamask.io',
      'etherscan.io',
      // allowlist subdomains
      'www.metamask.io',
      'faucet.metamask.io',
      'zero.metamask.io',
      'zero-faucet.metamask.io',
      'www.myetherwallet.com',
    ], currentConfig)

    // fuzzy

    testFuzzylist(t, [
      'metmask.io',
      'myetherwallet.cx',
      'myetherwallet.aaa',
      'myetherwallet.za',
      'myetherwallet.z',
    ], currentConfig)

    // DO NOT detected as phishing

    testAnyType(t, false, [
      'example.com',
      'ethereum.org',
      'etherid.org',
      'ether.cards',
      'easyeth.com',
      'etherdomain.com',
      'ethnews.com',
      'cryptocompare.com',
      'kraken.com',
      'myetherwallet.groovehq.com',
      'dether.io',
      'ethermine.org',
      'slaask.com',
      'ethereumdev.io',
      'ethereumdev.kr',
      'etherplan.com',
      'etherplay.io',
      'ethtrade.org',
      'ethereumpool.co',
      'estream.to',
      'ethereum.os.tc',
      'theethereum.wiki',
      'taas.fund',
      'tether.to',
      'ether.direct',
      'themem.io',
      'metajack.im',
      'mestatalsl.biz',
      'thregg.com',
      'steem.io',
      'ethereum1.cz',
      'metalab.co',
      'originprotocol.com'
    ], currentConfig)

    // DO INDEED detect as phishing
    testAnyType(t, true, [
      'etherdelta-glthub.com',
      'omise-go.com',
      'omise-go.net',
      'numerai.tech',
      'decentraiand.org',
      'myetherwallet.com.ethpromonodes.com',
      'blockcrein.info',
      'blockchealn.info',
      'bllookchain.info',
      'blockcbhain.info',
      'tokenswap.org',
      'ethtrade.io',
      'myetherwallèt.com',
      'myetherwallet.cm',
      'myethervvallet.com',
      'metherwallet.com',
      'mtetherwallet.com',
      'my-etherwallet.com',
      'my-etherwallet.in',
      'myeherwallet.com',
      'myetcwallet.com',
      'myetehrwallet.com',
      'myeterwallet.com',
      'myethe.rwallet.com',
      'myethereallet.com',
      'myetherieumwallet.com',
      'myetherswallet.com',
      'myetherw.allet.com',
      'myetherwal.let.com',
      'myetherwalet.com',
      'myetherwaliet.com',
      'myetherwall.et.com',
      'myetherwaller.com',
      'myetherwallett.com',
      'myetherwaillet.com',
      'myetherwalllet.com',
      'myetherweb.com.de',
      'myethetwallet.com',
      'myethewallet.com',
      'myÄ—therwallet.com',
      'myelherwallel.com',
      'mvetherwallet.com',
      'myethewallet.net',
      'myetherwillet.com',
      'myetherwallel.com',
      'myeltherwallet.com',
      'myelherwallet.com',
      'wwwmyetherwallet.com',
      'myethermwallet.com',
      'myeth4rwallet.com',
      'myethterwallet.com',
      'origirprotocol.com'
    ], currentConfig)

    // etc...

    testNoMatch(t, [
      'MetaMask',
      'localhost',
      'bancor',
      '127.0.0.1',
    ], currentConfig)

    t.end()
  })


  test('alexa top sites', (t) => {
    testAnyType(t, false, alexaTopSites, config)
    t.end()
  })

  test('popular dapps', (t) => {
    testAnyType(t, false, popularDapps, config)
    t.end()
  })

  test('MEW lists', (t) => {
    testListIsPunycode(t, mewWhitelist)
    testListIsPunycode(t, mewBlacklist)
    testAnyType(t, false, mewWhitelist, config)
    testAnyType(t, true, mewBlacklist, config)
    t.end()
  })

  // make sure all metamask phishing hits are explicitly blocklisted
  test('metamask gaq', (t) => {
    testListIsPunycode(t, metamaskGaq)
    const detector = new PhishingDetector(config)
    metamaskGaq.forEach((domain) => {
      const value = detector.check(domain)
      // enforcing type is optional
      // if (value.type === 'all') {
      //   t.comment(`'${domain}' was NOT identified as phishing`)
      // }
      t.notEqual(value.type, 'fuzzy', `MetaMask Gaq result: '${domain}' should NOT be 'fuzzy'`)
    })
    t.end()
  })

  test('config exclusively using punycode', (t) => {
    testListIsPunycode(t, config.whitelist)
    testListIsPunycode(t, config.fuzzylist)
    testListIsPunycode(t, config.blacklist)
    t.end()
  })

  test('config not repetitive', (t) => {
    testListDoesntContainRepeats(t, config.whitelist)
    testListDoesntContainRepeats(t, config.fuzzylist)
    testListDoesntContainRepeats(t, config.blacklist)
    t.end()
  })

  test('all fuzzylist entries are present in allowlist', (t) => {
    testListIsContained(t, config.fuzzylist, config.whitelist)
    t.end()
  })

  test('config only includes domains', (t) => {
    testListOnlyIncludesDomains(t, config.whitelist)
    testListOnlyIncludesDomains(t, config.fuzzylist)
    testListOnlyIncludesDomains(t, config.blacklist)
    t.end()
  })

  test('config does not contain redundant entries', (t) => {
    testListNoBlocklistRedundancies(t, config)
    testListNoAllowlistRedundancies(t, config)
    t.end()
  })
}

module.exports = {
  runTests,
}
