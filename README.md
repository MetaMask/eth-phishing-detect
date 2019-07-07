# eth-phishing-detect

[![Greenkeeper badge](https://badges.greenkeeper.io/MetaMask/eth-phishing-detect.svg)](https://greenkeeper.io/)

Utility for detecting phishing domains targeting Ethereum users.

For checking why a given domain was blocked, try our interactive page [here](https://metamask.github.io/eth-phishing-detect)

### basic usage

```js
const checkForPhishing = require('eth-phishing-detect')

const value = checkForPhishing('etherclassicwallet.com')
console.log(value) // true
```

### advanced usage

```js
const PhishingDetector = require('eth-phishing-detect/src/detector')

const detector = new PhishingDetector({ whitelist, blacklist, fuzzylist, tolerance })
const value = detector.check('etherclassicwallet.com')
console.log(value)
/*
{
  type: "blacklist",
  result: true,
}
*/
```
