# eth-phishing-detect

[![Greenkeeper badge](https://badges.greenkeeper.io/MetaMask/eth-phishing-detect.svg)](https://greenkeeper.io/)

List of malicious domains targeting Web3 users.

For checking why a given domain was blocked, there is a third-party [search tool](https://app.chainpatrol.io/search) maintained by ChainPatrol.

## Blocking Policy

We are constantly evolving the ideal policy that guides this list, but a few clearly defined rules have emerged. We will be quick and decisive to block websites that:

-   Impersonate other known and established sites.
-   Use their interfaces to collect user signing keys (especially cryptocurrency keys) and send them back to home servers.

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
addDomains(config, "blocklist", ["crypto-phishing-site.tld"]);
addDomains(config, "allowlist", ["legitimate-site.tld"]);
```

### Removing existing domains

```bash
yarn remove:blocklist legitimate-site.tld
yarn remove:allowlist malicious-site.tld
```

```js
removeDomains(config, "blocklist", ["legitimate-site.tld"]);
removeDomains(config, "allowlist", ["crypto-phishing-site.tld"]);
```

## Safeguards

We maintain trusted comparison lists in `test/resources`. Each file is plaintext with one host per line and is used by CI to reduce the risk of false positives. These lists include sources such as Tranco, CoinMarketCap, CoinGecko, the Snaps registry, and known dapps.

During `yarn test` / `yarn ci`, the list tests compare `src/config.json`'s `blacklist` entries against these trusted lists. If a blocklisted domain appears on one of the trusted lists and is not already bypassed, CI fails with the domain in the failure message. This is intentional: domains on these lists are often legitimate, so blocking them should require extra review.

Sometimes a trusted domain still needs to be blocked, for example during a DNS compromise, frontend compromise, or active malicious takeover. In those cases, add the exact blocklist entry to `test/resources/trusted-list-bypass.txt` with evidence or a short reason when possible:

```text
example.com # DNS compromise confirmed: https://example.com/evidence
```

Reviewers listed in `.github/trusted-list-bypass-reviewers.json` can also comment `/skip-trusted-lists` on a pull request. The automation will:

1. Confirm that the commenter is approved to request trusted-list bypasses.
2. Find trusted-list failures caused by the PR's current blocklist changes.
3. Append the required entries to `test/resources/trusted-list-bypass.txt`.
4. Commit the bypass file update back to the pull request branch so CI can rerun.

The automation can only push updates to pull request branches in this repository. For forked pull requests, a maintainer must apply the bypass file update manually.

To update the lists, run `yarn update:lists`. Note that you'll need a CoinMarketCap Pro API key.

## Auditing submissions & removals

Running the command below will pull all pull requests associated to example.com.

`git log -S "example.com" -- src/config.json`
