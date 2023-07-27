const test = require("tape");
const { testDomain } = require("./test.util.js");
const join = require("path").join;
const sqlite3 = require("sqlite3").verbose();

const DB_PATH = join(__dirname) + "/db";
const trancoDb = new sqlite3.Database(DB_PATH + "/tranco.db");
const coinmarketcapDb = new sqlite3.Database(DB_PATH + "/coinmarketcap.db");


function runTests(config) {
  test("check config blocklist against Tranco domains", async (t) => {
    let foundWhitelistedDomains = [];
    trancoDb.parallelize(() => {
      config.blacklist.forEach((BlacklistDomain, index) => {
        trancoDb.get(
          "SELECT domain FROM tranco WHERE domain = ?",
          BlacklistDomain,
          function (err, row) {
            if (row) {
              foundWhitelistedDomains.push(row.domain);
            }
          }
        );
      });
    });

    trancoDb.close(function (err) {
      if (foundWhitelistedDomains.length > 0) {
        t.fail(
          `Following domains found in tranco whitelist: "${foundWhitelistedDomains}" `
        );
      }
    });
  });

  test("check config blocklist against Coinmarketcap coins domains", async (t) => {
    let foundWhitelistedDomains = [];
    coinmarketcapDb.parallelize(() => {
      config.blacklist.forEach((BlacklistDomain, index) => {
        coinmarketcapDb.get(
          "SELECT domain FROM coinmarketcap WHERE domain = ?",
          BlacklistDomain,
          function (err, row) {
            if (row) {
              foundWhitelistedDomains.push(row.domain);
            }
          }
        );
      });
    });

    coinmarketcapDb.close(function (err) {
      if (foundWhitelistedDomains.length > 0) {
        t.fail(
          `Following domains found in Coinmarketcap coins domains: "${foundWhitelistedDomains}" `
        );
      }
    });
  });
}

module.exports = {
  runTests,
};
