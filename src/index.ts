const PhishingDetector = require('./detector')
import * as config from './config.json'

const detector = new PhishingDetector(config)

module.exports = checkDomain


function checkDomain(domain:string) {
  return detector.check(domain).result
}