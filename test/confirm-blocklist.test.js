const test = require("tape");
const fs = require("fs");
const path = require("path");

const DB_PATH = path.join(__dirname, "db");

// This is a list of "bad domains" (false positive) that we don't want to include in the Tranco test
const excludeList = [
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
];

function runTests(config) {
  testList = (listname, filename) => {
    test(`check config blocklist against ${listname} list`, (t) => {
      const domains = new Set(
        fs
          .readFileSync(path.join(DB_PATH, filename), { encoding: "utf-8" })
          .split("\n")
      );
      const foundOverlapping = config.blacklist.filter(
        (d) => domains.has(d) && !excludeList.includes(d)
      );
      t.equal(
        foundOverlapping.length,
        0,
        `Following domains found in ${listname} list: "${foundOverlapping}"`
      );
      t.end();
    });
  }

  testList("Tranco", "trancos.txt");
  testList("CoinMarketCap", "coinmarketcaps.txt");
  testList("MetaMask Snaps Registry", "snapsregistry.txt");
}

module.exports = {
  runTests,
};
