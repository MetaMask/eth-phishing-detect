# eth-phishing-detect

[![Greenkeeper badge](https://badges.greenkeeper.io/MetaMask/eth-phishing-detect.svg)](https://greenkeeper.io/)

Utility for detecting phishing domains targeting Web3 users.

For checking why a given domain was blocked, there is a third-party [search tool](https://app.chainpatrol.io/search) maintained by ChainPatrol.

## Blocking Policy

We are constantly evolving the ideal policy that guides this list, but a few clearly defined rules have emerged. We will be quick and decisive to block websites that:
- Impersonate other known and established sites.
- Use their interfaces to collect user signing keys (especially cryptocurrency keys) and send them back to home servers.

There are other grounds for blocking, and we will ultimately do our best to keep our users safe.

### Usage

As of v2.0.0, the detector logic has been moved to [`@metamask/phishing-controller`](https://github.com/MetaMask/core/tree/main/packages/phishing-controller) and this repo only holds the list of entries.


## Contributions


For understanding the lists, see [`doc/lists-ref.md`](doc/lists-ref.md).
Contributors are encouraged to read [`CONTRIBUTING.md`](./CONTRIBUTING.md) for tips, pointers, and guidelines before reporting or collaborating.

## Databases

We have added sqlite databases in `test/db` directory. These will be committed to the working tree periodically to try reduce the amount of false positives being blocklisted. We will pull in domains from various third party sources - right now: CoinMarketCap and Tranco. 

Update the database files:

```terminal
yarn update:db

yarn update:db:tranco
yarn update:db:coinmarketcap
yarn update:db:snapsregistry
```

These sqlite databases will be checked against in `yarn run test` to ensure nothing is on the blocklist that is also in these databases.
