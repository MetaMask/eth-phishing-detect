# config.json: whitelist

The `whitelist` object defined in src/config.json is a list of domains or subdomains vetted and confirmed non-malicious.

Contributors may also call the `whitelist` object the *allowlist* for clarity.

The only requirement for whitelist addition is that the domain or subdomain is *not* a *phishing scam*, as this repository's sole goal is to stop phishing scams.
Adding additional goals can put unnecessary strain on contributors; other projects may indeed have broader objectives and helping with those as well is a great way to fight scammers.

Generally the process of adding a whitelist entry is as follows:

1. Add a properly-formatted line to the whitelist object in `src/config.json`.
1. Commit your single addition with the message "`Allowlist [domain or subdomain] ([relevant filed issue, if applicable])`
1. File a pull request for this addition or multiple additions. Make sure this PR includes `Fixes #[issue]` if the PR fixes any relevant issues, and hyperlinks any relevant but unfixed issues.

The process of adding a site to the whitelist may look like the following or these steps may be very different for you, depending on your tooling:
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
