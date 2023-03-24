# eth-phishing-detect

[![Greenkeeper badge](https://badges.greenkeeper.io/MetaMask/eth-phishing-detect.svg)](https://greenkeeper.io/)

Utility for detecting phishing domains targeting Web3 users.

For checking why a given domain was blocked, try our interactive page [here](https://metamask.github.io/eth-phishing-detect) (outdated)

## Blocking Policy

We are constantly evolving the ideal policy that guides this list, but a few clearly defined rules have emerged. We will be quick and decisive to block websites that:
- Impersonate other known and established sites.
- Use their interfaces to collect user signing keys (especially cryptocurrency keys) and send them back to home servers.

There are other grounds for blocking, and we will ultimately do our best to keep our users safe.


### Basic usage

```js
const checkForPhishing = require('eth-phishing-detect')

const value = checkForPhishing('etherclassicwallet.com')
console.log(value) // true
```

### Advanced usage

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

Contributors are encouraged to read [`CONTRIBUTING.md`](./CONTRIBUTING.md) to for tips, pointers, and guidelines before reporting or collaborating.

To keep a tidy file, use the following CLI to make changes to the list:

### Adding hosts to blocklist

```
yarn add:blocklist crypto-phishing-site.tld
```

### Adding hosts to allowlist

```
yarn add:allowlist crypto-phishing-site.tld
```

# Blocklist vs Fuzzylist vs Allowlist
The **blocklist** redirects MetaMask users to a red warning screen instead of the website in question.
It was originally developed so that we had our own version of Chrome's "malicious website ahead!" page that we could update more quickly in response to our users. We primarily block sites that are actively attempting to phish our users, (i.e.,look-alike sites targeting those who hold crypto, DeFi degens, NFT lovers, etc.). 

We have the utmost respect for all those building products, experimenting with AI, and/or doing research around more robust ways to prevent all forms of cybercrime and fight back against scammers. However, the purpose of this specific repo is simply to collaborate and maintain a very long list of **active**, **malicious**, and **objectively harmful** websites targeting those in the cryptocurrency industry. We take a lot of pride in knowing that this list has prevented the theft of millions and millions of dollars over the past five years, and welcome those who wish to help us continue to do so.

The **fuzzylist** uses the Levenshtein distance algorithm and similar measures to proactively block URLs that are very similar to legitimate, highly-targeted websites without needing to add each new url to the blocklist. Generally speaking, the rule of thumb is: **don't add anything to the fuzzylist!**

The fuzzylist is really a relic from a time where the ecosystem was smaller and the products had longer, more unique names (e.g., MyEtherWallet, MetaMask). Adding `myetherwallet.com` to the fuzzylist will block `myetherwalllet.com` and `myethrwallet.com` and `myetherwa11et.com`. 

Today, due to the ever-growing number of products in the space and the reality that tens of millions of people have MetaMask installed, **the risk of adding a website to the fuzzylist almost always outweighs the potential benefits of doing so.** Should one decide that it would be genuinely beneficial to add a new URL to the fuzzylist, they should be prepared to respond to all reports of legitimate websites suddenly being blocked by MetaMask and ensure these legitimate websites are added to the allowlist promptly. Additionally, if maintainers of this repo notice a consistent pattern of websites needing to be added to the allowlist, it may be worth removing the similarly-named URL from the fuzzylist instead of continuing to add websites to the allowlist.

The **allowlist** simply ensures that a specific URL will **not** be blocked. Specifically, if a legitimate website is being blocked by MetaMask but it is **not** found on the blocklist, adding it to the allowlist is the fastest and simplest way to unblock that specific website quickly.

Note: Opening a valid pull request to add a website to the allowlist will generally be faster than opening an issue asking us to do so. You may feel compelled to politely ping the maintainers of this repo or MetaMask employees directly in an attempt to speed up the process and, as long as you are polite, we understand and will try to help in cases where the matter is urgent. 

