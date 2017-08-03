# eth-phishing-detect

Utility for detecting phishing domains targeting Ethereum users.

### basic usage

```js
const checkForPhishing = require('eth-phishing-detect')

const value = checkForPhishing('etherclassicwallet.com')
console.log(value) // true
```

### advanced usage

```js
const PhishingDetector = require('eth-phishing-detect/src/detector')

const detector = new PhishingDetector({ whitelist, blacklist, tolerance })
const value = detector.check('etherclassicwallet.com')
console.log(value)
/*
{
  type: "blacklist",
  result: true,
}
*/
```