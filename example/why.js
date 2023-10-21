const PhishingDetector = require('../src/detector')

let phishing;
let detector;

fetch('https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json')
  .then(response => response.json())
  .then(data => {
    phishing = data;
    detector = new PhishingDetector(phishing);
  })
  .catch(error => console.error('Error:', error));

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