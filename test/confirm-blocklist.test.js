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
  "multichain.org", //https://twitter.com/MultichainOrg/status/1677180114227056641
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
