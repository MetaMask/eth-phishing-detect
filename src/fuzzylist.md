# config.json: fuzzylist

The `fuzzylist` object defined in src/config.json is a list of URLs of whose users are frequently targeted in phishing attacks.
Accessed sites are checked against the fuzzylist; they're stripped of `/^www\./` and their approximate top-level domain
(anything after the last full stop; [`.com` is stripped correctly but `.co.uk` will turn into `.co`](https://github.com/MetaMask/eth-phishing-detect/issues/5409))
and then are checked for their [Levenshtein distance](https://en.wikipedia.org/wiki/Levenshtein_distance) from each fuzzylist entry.
If their Levenshtein distance from a fuzzylist entry is [less than or equal to](https://github.com/MetaMask/eth-phishing-detect/blob/master/src/detector.js#L33)
the tolerance (which [defaults to `3`](https://github.com/MetaMask/eth-phishing-detect/blob/master/src/detector.js#L2)
but is [configured to be `2` in src/config.json](https://github.com/MetaMask/eth-phishing-detect/blob/master/src/config.json#L3))
the site is flagged as a potential phishing site.

## commit history

This list may not be complete.
Please correct any mistakes if found.

- *ethereum.org*
  - commit [8a3572ba2](https://github.com/MetaMask/eth-phishing-detect/commit/8a3572ba2) (2017-08-03)
  - removed [1f89580](https://github.com/MetaMask/eth-phishing-detect/commit/1f89580) (2017-08-06)

- metamask.io
  - commit [8a3572ba2](https://github.com/MetaMask/eth-phishing-detect/commit/8a3572ba2) (2017-08-03)

- myetherwallet.com
  - commit [8a3572ba2](https://github.com/MetaMask/eth-phishing-detect/commit/8a3572ba2) (2017-08-03)

- cryptokitties.co
  - commit [3112e8d](https://github.com/MetaMask/eth-phishing-detect/commit/3112e8d) (2017-12-12)

- *mycrypto.com*
  - commit [7c7fbaa51](https://github.com/MetaMask/eth-phishing-detect/commit/7c7fbaa51) (2018-02-09)
  - removed [97d6514](https://github.com/MetaMask/eth-phishing-detect/commit/97d6514) (2021-01-29)

- localethereum.com
  - commit [8931f9b](https://github.com/MetaMask/eth-phishing-detect/commit/8931f9b) (2018-02-24)

- dfinity.org
  - commit [045b1c5](https://github.com/MetaMask/eth-phishing-detect/commit/045b1c5) (2018-03-01)

- hederahashgraph.com
  - commit [a37fc6d](https://github.com/MetaMask/eth-phishing-detect/commit/a37fc6d) (2018-03-22)

- auctus.org
  - commit [2eb1e8a](https://github.com/MetaMask/eth-phishing-detect/commit/2eb1e8a) (2018-03-27)

- etherscan.io
  - commit [5e0e11e](https://github.com/MetaMask/eth-phishing-detect/commit/5e0e11e) (2018-04-16)

- originprotocol.com
  - commit [07350b8](https://github.com/MetaMask/eth-phishing-detect/commit/07350b8) (2018-04-21)

- localcryptos.com
  - commit [c50c8be](https://github.com/MetaMask/eth-phishing-detect/commit/c50c8be) (2019-12-20)

- *makerdao.com*
  - commit [acbe1a3](https://github.com/MetaMask/eth-phishing-detect/commit/acbe1a3) (2020-01-21)
  - removed [d5fc3f5](https://github.com/MetaMask/eth-phishing-detect/commit/d5fc3f5) (2021-07-06)

- makerfoundation.com
  - commit [acbe1a3](https://github.com/MetaMask/eth-phishing-detect/commit/acbe1a3) (2020-01-21)

- *mkr.tools*
  - commit [acbe1a3](https://github.com/MetaMask/eth-phishing-detect/commit/acbe1a3) (2020-01-21)
  - removed [5c03787](https://github.com/MetaMask/eth-phishing-detect/commit/5c03787) (2021-01-21)

- *oasis.app*
  - commit [acbe1a3](https://github.com/MetaMask/eth-phishing-detect/commit/acbe1a3) (2020-01-21)
  - removed [8176449](https://github.com/MetaMask/eth-phishing-detect/commit/8176449) (2020-03-02)

- fulcrum.trade
  - commit [e066f83](https://github.com/MetaMask/eth-phishing-detect/commit/e066f83) (2020-07-19)

- *uniswap.org*
  - commit [63e146a](https://github.com/MetaMask/eth-phishing-detect/commit/63e146a) (2020-08-04)
  - removed [24c3d67](https://github.com/MetaMask/eth-phishing-detect/commit/24c3d67) (2020-11-10)

- *ledger.com*
  - commit [ea60277](https://github.com/MetaMask/eth-phishing-detect/commit/ea60277) (2020-10-31)
  - removed [e90c5de](https://github.com/MetaMask/eth-phishing-detect/commit/e90c5de) (2020-11-06)

- launchpad.ethereum.org
  - commit [ae7b882](https://github.com/MetaMask/eth-phishing-detect/commit/ae7b882) (2020-11-04)

- maskmeta.org
  - commit [1783765](https://github.com/MetaMask/eth-phishing-detect/commit/1783765) (2020-12-16)

- opensea.io
  - commit [c8c52f8](https://github.com/MetaMask/eth-phishing-detect/commit/c8c52f8) (2021-09-22)
