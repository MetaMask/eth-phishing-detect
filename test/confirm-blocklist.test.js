const test = require("tape");
const { testDomain } = require("./test.util.js");
const join = require("path").join;
const sqlite3 = require("sqlite3").verbose();

const DB_PATH = join(__dirname) + "/db";
const trancoDb = new sqlite3.Database(DB_PATH + "/tranco.db");
const coinmarketcapDb = new sqlite3.Database(DB_PATH + "/coinmarketcap.db");


function runTests(config) {
  test("check config blocklist against Tranco domains", async (t) => {
    let foundListedDomains = [];
    trancoDb.parallelize(() => {
      config.blacklist.forEach((blacklistDomain) => {
        trancoDb.get(
          "SELECT domain FROM tranco WHERE domain = ?",
          blacklistDomain,
          function (err, row) {
            t.error(err, 'Sqlite db error');
            if (row) {
              foundListedDomains.push(row.domain);
            }
          }
        );
      });
    });

    trancoDb.close(function (err) {
      t.error(err, 'Sqlite db error');
      t.equal(
        foundListedDomains.length, 0,
        `Following domains found in tranco list: "${foundListedDomains}" `
      );
    });
  });

  test("check config blocklist against Coinmarketcap coins domains", async (t) => {
    let foundListedDomains = [];
    coinmarketcapDb.parallelize(() => {
      config.blacklist.forEach((blacklistDomain) => {
        coinmarketcapDb.get(
          "SELECT domain FROM coinmarketcap WHERE domain = ?",
          blacklistDomain,
          function (err, row) {
            t.error(err, 'Sqlite db error');
            if (row) {
              foundListedDomains.push(row.domain);
            }
          }
        );
      });
    });

    coinmarketcapDb.close(function (err) {
      t.error(err, 'Sqlite db error');
      t.equal(
        foundListedDomains.length, 0,
        `Following domains found in Coinmarketcap coins domains: "${foundListedDomains}" `
      );
    });
  });
}

module.exports = {
  runTests,
};
