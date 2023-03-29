# Blocklist vs Fuzzylist vs Allowlist
The **blocklist** redirects MetaMask users to a red warning screen instead of the website in question.
It was originally developed so that we had our own version of Chrome's "malicious website ahead!" page that we could update more quickly in response to our users. We primarily block sites that are actively attempting to phish our users, (i.e.,look-alike sites targeting those who hold crypto, DeFi degens, NFT lovers, etc.).

We have the utmost respect for all those building products, experimenting with AI, and/or doing research around more robust ways to prevent all forms of cybercrime and fight back against scammers. However, the purpose of this specific repo is simply to collaborate and maintain a very long list of **active**, **malicious**, and **objectively harmful** websites targeting those in the cryptocurrency industry. We take a lot of pride in knowing that this list has prevented the theft of millions and millions of dollars over the past five years, and welcome those who wish to help us continue to do so.

The **fuzzylist** uses the Levenshtein distance algorithm and similar measures to proactively block URLs that are very similar to legitimate, highly-targeted websites without needing to add each new url to the blocklist. Generally speaking, the rule of thumb is: **don't add anything to the fuzzylist!**

The fuzzylist is really a relic from a time where the ecosystem was smaller and the products had longer, more unique names (e.g., MyEtherWallet, MetaMask). Adding `myetherwallet.com` to the fuzzylist will block `myetherwalllet.com` and `myethrwallet.com` and `myetherwa11et.com`.

Today, due to the ever-growing number of products in the space and the reality that tens of millions of people have MetaMask installed, **the risk of adding a website to the fuzzylist almost always outweighs the potential benefits of doing so.** Should one decide that it would be genuinely beneficial to add a new URL to the fuzzylist, they should be prepared to respond to all reports of legitimate websites suddenly being blocked by MetaMask and ensure these legitimate websites are added to the allowlist promptly. Additionally, if maintainers of this repo notice a consistent pattern of websites needing to be added to the allowlist, it may be worth removing the similarly-named URL from the fuzzylist instead of continuing to add websites to the allowlist.

The **allowlist** simply ensures that a specific URL will **not** be blocked. Specifically, if a legitimate website is being blocked by MetaMask but it is **not** found on the blocklist, adding it to the allowlist is the fastest and simplest way to unblock that specific website quickly.

Note: Opening a valid pull request to add a website to the allowlist will generally be faster than opening an issue asking us to do so. You may feel compelled to politely ping the maintainers of this repo or MetaMask employees directly in an attempt to speed up the process and, as long as you are polite, we understand and will try to help in cases where the matter is urgent.

## config.json: allowlist

The `allowlist` object defined in src/config.json is a list of domains or subdomains vetted and confirmed non-malicious.

Contributors may also call the `allowlist` object the *allowlist* for clarity.

The only requirement for allowlist addition is that the domain or subdomain is *not* a *phishing scam*, as this repository's sole goal is to stop phishing scams.
Adding additional goals can put unnecessary strain on contributors; other projects may indeed have broader objectives and helping with those as well is a great way to fight scammers.

Generally the process of adding a allowlist entry is as follows:

1. Add a properly-formatted line to the allowlist object in `src/config.json`.
2. Commit your single addition with the message "`Allowlist [domain or subdomain] ([relevant filed issue, if applicable])`
3. File a pull request for this addition or multiple additions. Make sure this PR includes `Fixes #[issue]` if the PR fixes any relevant issues, and hyperlinks any relevant but unfixed issues.

The process of adding a site to the allowlist may look like the following or these steps may be very different for you, depending on your tooling:
```
$ git clone git@github.com:MetaMask/eth-phishing-detect.git
Cloning into 'eth-phishing-detect'...
remote: Enumerating objects: 20570, done.
remote: Counting objects: 100% (437/437), done.
remote: Compressing objects: 100% (282/282), done.
remote: Total 20570 (delta 295), reused 263 (delta 155), pack-reused 20133
Receiving objects: 100% (20570/20570), 7.43 MiB | 2.37 MiB/s, done.
Resolving deltas: 100% (10664/10664), done.
$ cd eth-phishing-detect
$ git branch patch-1
$ git checkout patch-1
Switched to branch 'patch-1'
$ vi src/config.json
$ git diff src/config.json
diff --git a/src/config.json b/src/config.json
index b94569f8..55418838 100644
--- a/src/config.json
+++ b/src/config.json
@@ -19,6 +19,7 @@
     "originprotocol.com"
   ],
   "whitelist": [
+    "example.com",
     "infinity.exchange",
     "otterscan.io",
     "olympusdao.finance",
$ git add src/config.json
$ git commit -m "Allowlist example.com (#0000)"
$ git push
```

## config.json: fuzzylist

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
