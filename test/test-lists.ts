import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from "tape";
import { Config } from '../src/types';
import { detectFalsePositives, parseDomainWithCustomPSL } from './utils';

// This is a list of "bad domains" (false positive) that we don't want to include in the Tranco test
const bypass = new Set([
    "mystrikingly.com",
    "simdif.com",
    "gb.net",
    "btcs.love",
    "ferozo.com",
    "im-creator.com",
    "free-ethereum.io",
    "890m.com",
    "b5z.net",
    "test.com",
    "multichain.org", // https://twitter.com/MultichainOrg/status/1677180114227056641
    "dydx.exchange", // https://x.com/dydx/status/1815780835473129702
    "ambient.finance", // https://x.com/pcaversaccio/status/1846851269207392722
    "xyz.cutestat.com",

    /* 
    // Below are unknown websites that should stay on the blocklist for brevity but make tests fail. This is likely because they exist on the
    // Tranco list and for one reason or another have a high repuatation score.
  
    // NOTE: If it is on the Tranco list, please CONFIRM that you are NOT adding a false positive. This will trigger a manual review within the CICD pipeline.
    Only once it is confirmed not to be a false positive can it be added to this list.
    */
    "azureserv.com",
    "dnset.com",
    "dnsrd.com",
    "prohoster.biz",
    "kucoin.plus",
    "ewp.live",
    "sdstarfx.com",
    "1mobile.com",
    "v6.rocks",
    "linkpc.net",
    "bookmanga.com",
    "lihi.cc",
    "mytradift.com",
    "anondns.net",
    "bitkeep.vip",
    "temporary.site",
    "misecure.com",
    "myz.info",
    "ton-claim.org",
    "servehalflife.com",
    "earnstations.com",
    "web3quests.com",
    "qubitscube.com",
    "teknik.io",
    "nflfan.org",
    "purworejokab.go.id",
    "ditchain.org",
    "kuex.com",
    "cloud.dbank.com",
    "bybi75-alternate.app.link",
    "mz4t6.rdtk.io",
    "tornadoeth.cash",
    "ether.fi", // https://x.com/ether_fi/status/1838643492102283571
    "curve.fi" // https://x.com/CurveFinance/status/1922040492121829678
]);

export const runTests = (config: Config) => {
    const testList = (listId: string) => {
        test(`ensure no domains on allowlist are blocked: ${listId}`, async (t) => {
            const contents = await readFile(path.join(__dirname, "resources", `${listId}.txt`), { encoding: 'utf-8' });

            const domains = new Set(contents.split("\n"));

            const falsePositives = detectFalsePositives(config.blacklist!, domains, bypass);

            t.equal(falsePositives.length, 0, `The following domains should not be blocked: ${falsePositives}`);

            t.end();
        });
    };

    testList("tranco");
    testList("coinmarketcap");
    testList("snapsregistry");
    testList("coingecko");
    testList("dapps");
};

