const test = require("tape");
const PhishingDetector = require("../src/detector.js");
const { testDomain } = require("./test.util.js");
const parseCsv = require("csv-parse/sync");
const fs = require("fs");

function runTests(config) {
  test("check config blocklist against whitelist", (t) => {
    const alexaDomainsCsv = fs.readFileSync(
      __dirname + "/alexaDomains.csv",
      "utf8"
    );
    const alexaDomains = parseCsv
      .parse(alexaDomainsCsv, {
        skip_empty_lines: true,
      })
      .flat();

    const options = [
      {
        allowlist: alexaDomains,
        blocklist: [],
        fuzzylist: [],
        name: "first",
        tolerance: 0,
        version: 1,
      },
    ];

    const detector = new PhishingDetector(options);

    config.blacklist.forEach((domain) => {
      // First method
      /* const value = alexaDomains.includes(domain);
      t.equal(value, false, `result: "${domain}" not found in: "allowlist"`); */
      // Second method
      const value = detector.check(domain);
      t.notEqual(
        value.type,
        "allowlist",
        `result: "${domain}" not found in: "allowlist"`
      );
    });

    t.end();
  });
}

module.exports = {
  runTests,
};
