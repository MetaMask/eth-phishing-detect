import test from "tape";
import {
    testAllowlist,
    testAnyType,
    testBlocklist,
    testFuzzylist,
    testListDoesntContainRepeats,
    testListIsContained,
    testListIsPunycode,
    testListNoConflictingEntries,
    testListOnlyIncludesDomains,
    testNoMatch,
} from "./utils.js";
import { Config } from "../src/types.js";

export const runTests = (config: Config) => {
    test("legacy config", (t) => {
        // blocklist

        testBlocklist(
            t,
            [
                "metamask.com",
                "tornadoeth.cash",
                "tornadoeth.cash.", //Test for absolute fully-qualified domain name
                "test.metamask-phishing.io",
            ],
            config,
        );

        // allowlist

        testAllowlist(
            t,
            [
                "metamask.io",
                "etherscan.io",
                // allowlist subdomains
                "www.metamask.io",
                "faucet.metamask.io",
                "zero.metamask.io",
                "zero-faucet.metamask.io",
                "www.myetherwallet.com",
            ],
            config,
        );

        // fuzzy

        testFuzzylist(
            t,
            ["metmask.io", "myetherwallet.cx", "myetherwallet.aaa", "myetherwallet.za", "myetherwallet.z"],
            config,
        );

        // DO NOT detected as phishing

        testAnyType(
            t,
            false,
            [
                "localhost",
                "http",
                "https",
                "127.0.0.1",
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
                "originprotocol.com",
            ],
            config,
        );

        // DO INDEED detect as phishing
        testAnyType(
            t,
            true,
            [
            ],
            config,
        );

        // etc...

        testNoMatch(t, ["MetaMask", "bancor"], config);

        t.end();
    });

    test("current config", (t) => {
        const currentConfig = [
            {
                allowlist: config.whitelist,
                blocklist: config.blacklist,
                disputeUrl: "https://github.com/MetaMask/eth-phishing-detect",
                fuzzylist: config.fuzzylist,
                name: "MetaMask",
                tolerance: config.tolerance,
                version: config.version,
            },
        ];

        // blocklist

        testBlocklist(
            t,
            [
                "metamask.com",
                "tornadoeth.cash",
                "tornadoeth.cash.", //Test for absolute fully-qualified domain name
                "test.metamask-phishing.io",
            ],
            currentConfig,
        );

        // allowlist

        testAllowlist(
            t,
            [
                "metamask.io",
                "etherscan.io",
                // allowlist subdomains
                "www.metamask.io",
                "faucet.metamask.io",
                "zero.metamask.io",
                "zero-faucet.metamask.io",
                "www.myetherwallet.com",
            ],
            currentConfig,
        );

        // fuzzy

        testFuzzylist(
            t,
            ["metmask.io", "myetherwallet.cx", "myetherwallet.aaa", "myetherwallet.za", "myetherwallet.z"],
            currentConfig,
        );

        // DO NOT detected as phishing

        testAnyType(
            t,
            false,
            [
                "localhost",
                "http",
                "https",
                "127.0.0.1",
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
                "originprotocol.com",
            ],
            currentConfig,
        );

        // DO INDEED detect as phishing
        testAnyType(
            t,
            true,
            [
            ],
            currentConfig,
        );

        // etc...

        testNoMatch(t, ["MetaMask", "bancor"], currentConfig);

        t.end();
    });

    test("config exclusively using punycode", (t) => {
        testListIsPunycode(t, config.whitelist);
        testListIsPunycode(t, config.fuzzylist);
        testListIsPunycode(t, config.blacklist);
        t.end();
    });

    test("config not repetitive", (t) => {
        testListDoesntContainRepeats(t, config.whitelist);
        testListDoesntContainRepeats(t, config.fuzzylist);
        testListDoesntContainRepeats(t, config.blacklist);
        t.end();
    });

    test("all fuzzylist entries are present in allowlist", (t) => {
        testListIsContained(t, config.fuzzylist, config.whitelist);
        t.end();
    });

    test("config only includes domains", (t) => {
        testListOnlyIncludesDomains(t, config.whitelist);
        testListOnlyIncludesDomains(t, config.fuzzylist);
        testListOnlyIncludesDomains(t, config.blacklist);
        t.end();
    });

    test("config does not include conflicting allowlist and blocklist entries", (t) => {
        testListNoConflictingEntries(t, config);
        t.end();
    });

    // test('config does not contain redundant entries', (t) => {
    //   testListNoBlocklistRedundancies(t, config)
    //   // FIXME: temporarily disabled due to config propagation inconsistency
    //   // testListNoAllowlistRedundancies(t, config)
    //   t.end()
    // })
};
