This repo (`@MetaMask/eth-phishing-detect`) aims to be an open, auditable, list of malicious web3 domains to give advisory to those that ingest it to block interaction with those identified domains.

Whilst the list is managed by the MetaMask team (and select external contributors), it is heavily modified by external contributors who detect and report malicious domains to us; through issues or PRs or via one of the integration bots. We would like to extend our thanks to everyone who has and continued to contribute to these lists and help make the spacer safer for everyone.

Generally speaking, external contributors will only add entries to the blocklist, and each of their PR’s will be reviewed by someone from the review team before merging. Recently, some contributors have started using various bots to propose changes. Some of the entities developing the bots have been promoted into the reviewer team to help manage the list on scale and get new additions approved in a more timely fashion.

At a high-level, we will give contributors 2 chances to improve their contribution pipeline to reduce their false-positive rate.

* Going forward, the **first false-positive contribution** will **require us (MetaMask) to get on a call with the contributor and discuss their pipeline** in detail, and have them identify what went wrong and let them lead the **conversation on improvements they will make to their systems**.
   * If we (MetaMask) do not already have a private communication line with the contributor, we will ask for it in the PR that issued the false-positive. If we do not make contact with you after 3 business days, then we will skip to the last stage – revoking review permissions.

* On the **second false-positive contribution**, we will get on another call with the contributor and discuss their pipeline in detail again. **We will then lead the conversation on the changes they must implement to their systems**.

* On the **third false-positive contribution**, their **write/review access is revoked** and a conversation is started to review everything.