# eth-phishing-detect

[![Greenkeeper badge](https://badges.greenkeeper.io/MetaMask/eth-phishing-detect.svg)](https://greenkeeper.io/)

List of malicious domains targeting Web3 users.

For checking why a given domain was blocked, there is a third-party [search tool](https://app.chainpatrol.io/search) maintained by ChainPatrol.

## Blocking Policy

We are constantly evolving the ideal policy that guides this list, but a few clearly defined rules have emerged. We will be quick and decisive to block websites that:
- Impersonate other known and established sites.
- Use their interfaces to collect user signing keys (especially cryptocurrency keys) and send them back to home servers.

There are other grounds for blocking, and we will ultimately do our best to keep our users safe.


### Basic usage

UPDATE: The phishing detector has been moved [here](https://github.com/MetaMask/core/tree/main/packages/phishing-controller).

## Contributions

To keep a tidy file, use the CLI or library functions to modify the list.

### Adding new domains

```bash
yarn add:blocklist crypto-phishing-site.tld
yarn add:allowlist legitimate-site.tld
```

```js
addDomains(config, 'blocklist', ['crypto-phishing-site.tld']);
addDomains(config, 'allowlist', ['legitimate-site.tld']);
```

### Removing existing domains

```bash
yarn remove:blocklist legitimate-site.tld
yarn remove:allowlist malicious-site.tld
```

```js
removeDomains(config, 'blocklist', ['legitimate-site.tld']);
removeDomains(config, 'allowlist', ['crypto-phishing-site.tld']);
```

## Safeguards

We maintain a list of domains pulled from various sources in `test/resources`. Each file is plaintext with one host per domain. These domains are used to reduce the risk of false positives. If you need to block a domain that is featured on one of these lists, you'll need to add a bypass to `test/test-lists.ts`.

To update the lists, run `yarn update:lists`. Note that you'll need a CoinMarketCap Pro API key.
