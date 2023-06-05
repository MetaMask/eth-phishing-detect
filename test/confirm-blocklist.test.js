const test = require("tape");
const { testDomain } = require("./test.util.js");
const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./tranco.db");

function runTests(config) {
  test("check config blocklist against top Tranco domains", async (t) => {
    let foundWhitelistedDomains = [];
    db.parallelize(() => {
      config.blacklist.forEach((BlacklistDomain, index) => {
        db.get(
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

    db.close(function (err) {
      if (foundWhitelistedDomains.length > 0) {
        t.fail(
          `Following domains found in tranco whitelist: "${foundWhitelistedDomains}" `
        );
      }
    });
  });
}

module.exports = {
  runTests,
};
