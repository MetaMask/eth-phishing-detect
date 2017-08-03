const PhishingDetector = require('./detector')
const config = require('./config.json')

const detector = new PhishingDetector(config)

module.exports = checkDomain


function checkDomain(domain) {
  return detector.check(domain).result
}