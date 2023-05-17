const test = require("tape");
const PhishingDetector = require("../src/detector.js");
const { testDomain } = require("./test.util.js");
const parseCsv = require("csv-parse/sync");
const fs = require("fs");

function runTests(config) {
  test.skip("check config blocklist against alexa top domains", (t) => {
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
        `result: "${domain}" should not be in: "allowlist" at: ${value.match}`
      );
    });

    t.end();
  });

  test("check config blocklist against top Tranco domains", async (t) => {
    const trancoDomainsCsv = fs.readFileSync(
      __dirname + "/trancoTop1m.csv",
      "utf8"
    );
    const trancoDomains = parseCsv
      .parse(trancoDomainsCsv, {
        skip_empty_lines: true,
      })
      .flat();

    const options = [
      {
        allowlist: trancoDomains,
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
      /* const value = trancoDomains.includes(domain);
        t.equal(value, false, `result: "${domain}" not found in: "allowlist"`); */
      // Second method
      const value = detector.check(domain);
      t.notEqual(
        value.type,
        "allowlist",
        `result: "${domain}" should not be in "allowlist" at: ${value.match}`
      );
    });

    t.end();
  });

  test.skip("check config blocklist against top DappRadar dapps", async (t) => {
    const query = new URLSearchParams({
      chain: "string",
      category: "0",
      range: "24h",
      top: "10",
    }).toString();

    const metric = "YOUR_metric_PARAMETER";
    const project = "4tsxo4vuhotaojtl";
    const resp = await fetch(
      `https://api.dappradar.com/${project}/dapps/top/${metric}?${query}`,
      {
        method: "GET",
        headers: {
          "X-BLOBR-KEY": "YOUR_API_KEY_HERE",
        },
      }
    );

    const data = await resp.text();
    t.end();
  });
}

module.exports = {
  runTests,
};
