const test = require('tape')

const {
  testListDoesntContainRepeats,
  testListIsPunycode,
  testListNoConflictingEntries,
  testListOnlyIncludesDomains,
} = require('./test.util.js')
const alexaTopSites = require('./alexa.json')
const popularDapps = require('./dapps.json')

async function runTests ({ config }) {
  startTests({ config })
}

function startTests ({ config }) {

  /************************
   * 3rd-party list tests *
   ************************/

  /**
   * Ensure none of the Alexa top sites
   * are not explicitly in the blocklist
   */
  test('Alexa top sites not in blocklist', (t) => {
    const configList = new Set(config.blacklist);
    alexaTopSites.forEach((domain) => {
      if(configList.has(domain)) {
        t.error(`${domain} is in Alexa list so should not be in blocklist`)
      }
    });
    t.end();
  })

  /**
   * Ensure none of the popular dapps
   * are not explicitly in the blocklist
   */
  test('Popular dapps not in blocklist', (t) => {
    const configList = new Set(config.blacklist);
    popularDapps.forEach((domain) => {
      if(configList.has(domain)) {
        t.error(`${domain} is in popular dapp list so should not be in blocklist`)
      }
    });
    t.end();
  })

  /***************************
   * Repeating entries tests *
   ***************************/

  /**
   * Ensure there are no repeat entries
   * in the list.
   */
  test('List does not contain repeats', (t) => {
    testListDoesntContainRepeats(t, config.blacklist);
    testListDoesntContainRepeats(t, config.whitelist);
    testListDoesntContainRepeats(t, config.fuzzylist);
    t.end();
  })

  /******************
   * Punycode tests *
   ******************/
  
  /**
   * Ensure there are no punycode entries
   * in the list.
   */
    test('List does not contain punycode', (t) => {
      testListIsPunycode(t, config.whitelist);
      testListIsPunycode(t, config.blacklist);
      testListIsPunycode(t, config.fuzzylist);
      t.end();
    });

    /*******************************
     * List format tests *
     *******************************/
    
    /**
     * Ensure there are only domains or
     * ipfs cids in the list.
     */
    test('List only contains domains or ipfs cid', (t) => {
      testListOnlyIncludesDomains(t, config.whitelist);
      testListOnlyIncludesDomains(t, config.blacklist);
      testListOnlyIncludesDomains(t, config.fuzzylist);
      t.end();
    });

    /**
     * Ensure there are no conflicting
     * entries in the list.
     */
    test('List does not contain conflicting entries', (t) => {
      testListNoConflictingEntries(t, config.whitelist);
      testListNoConflictingEntries(t, config.blacklist);
      testListNoConflictingEntries(t, config.fuzzylist);
      t.end();
    });

}

module.exports = {
  runTests,
}
