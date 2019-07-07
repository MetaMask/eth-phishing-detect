const PhishingDetector = require('eth-phishing-detect/src/detector')
const fetch = require('isomorphic-fetch')
let phishing

updatePhishingList()
.then(() => {
  detector = new PhishingDetector(phishing)
})

async function updatePhishingList () {
  // make request
  let response
  try {
    response = await fetch('https://api.infura.io/v2/blacklist')
  } catch (err) {
    console.error(err)
    return
  }
  // parse response
  let rawResponse
  try {
    const rawResponse = await response.text()
    phishing = JSON.parse(rawResponse)
  } catch (err) {
    console.error(new Error(`BlacklistController - failed to parse blacklist:\n${rawResponse}`))
    return
  }
}

/*
 * A function for checking why a given domain is blocked.
 * @param { string } domain - The domain that is blocked.
 * @returns { string } reason - A string describing the reason for the block.
 */
function why (domain) {
  if (!detector) {
    return 'Cannot answer, still loading list data...'
  }

  const reason = detector.check(domain)

  if (!reason.result) {
    return 'This domain is not blocked! No problem here.'
  }

  if (reason.type === 'fuzzy') {
    return `This domain was blocked for its similarity to ${reason.match}, a historical phishing target.`
  }

  if (reason.type === 'blacklist') {
    return `This domain was blocked because it has been explicitly identified as a malicious site.`
  }

  return `There was an issue identifying the reason for the block. The data is ${JSON.stringify(reason)}`
}

module.exports = why

