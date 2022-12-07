# eth-phishing-detect

[![Greenkeeper badge](https://badges.greenkeeper.io/MetaMask/eth-phishing-detect.svg)](https://greenkeeper.io/)

Utility for detecting phishing domains targeting Ethereum users.

For checking why a given domain was blocked, try our interactive page [here](https://metamask.github.io/eth-phishing-detect)

## Blocking Policy

We are constantly evolving the ideal policy that guides this list, but a few clearly defined rules have emerged. We will be quick and decisive to block websites that:
- Impersonate other known and established sites.
- Use their interfaces to collect user signing keys (especially cryptocurrency keys) and send them back to home servers.

There are other grounds for blocking, and we will ultimately do our best to keep our users safe.

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

## Contributions

To keep a tidy file, use the following CLI to make changes to the list:

### Adding hosts to blocklist

```
yarn add:blocklist crypto-phishing-site.tld
```

### Adding hosts to allowlist

```
yarn add:allowlist crypto-phishing-site.tld
```
