const PhishingDetector = require('../src/detector')
let phishing = require('../src/config.json')

const detector = new PhishingDetector(phishing)

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

