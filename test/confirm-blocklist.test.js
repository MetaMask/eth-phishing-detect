const test = require("tape");
const fs = require("fs");
const path = require("path");

const DB_PATH = path.join(__dirname, "db");


function runTests(config) {
  test("check config blocklist against Tranco domains", (t) => {
    const trancos = new Set(fs.readFileSync(path.join(DB_PATH, "trancos"), {encoding: 'utf-8'}).split('\n'));
    const foundOverlapping = config.blacklist.filter(d => trancos.has(d));
    t.equal(foundOverlapping.length, 0, `Following domains found in Tranco domains: "${foundOverlapping}"`);
    t.end();
  });

  test("check config blocklist against Coinmarketcap coins domains", (t) => {
    const coinmarketcaps = new Set(fs.readFileSync(path.join(DB_PATH, "coinmarketcaps"), {encoding: 'utf-8'}).split('\n'));
    const foundOverlapping = config.blacklist.filter(d => coinmarketcaps.has(d));
    t.equal(foundOverlapping.length, 0, `Following domains found in Coinmarketcap coins domains: "${foundOverlapping}"`);
    t.end();
  });
}

module.exports = {
  runTests,
};
