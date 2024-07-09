const fs = require('fs')
const punycode = require('punycode/')
const needle = require('needle')
const parseCsv = require('csv-parse/sync')

function ipfsCidRegex(startEndMatch = true) {
  // regex from https://stackoverflow.com/a/67176726
  let reg = "Qm[1-9A-HJ-NP-Za-km-z]{44,}|b[A-Za-z2-7]{58,}|B[A-Z2-7]{58,}|z[1-9A-HJ-NP-Za-km-z]{48,}|F[0-9A-F]{50,}";
  if(startEndMatch) {
    reg = ["^", reg, "$"].join("");
  }
  return new RegExp(reg, "");
}

function formatHostnameToUrl (hostname) {
  let url;
    try {
      url = new URL(hostname).href;
  } catch(e) {
      if(e instanceof TypeError) {
        url = new URL(["https://", hostname].join("")).href;
      }
  }
  return url;
}

function loadMetamaskGaq () {
  // extract hits from Google Analytics data from metamask.io phishing warning
  // fetch from https://analytics.google.com/analytics/web/#my-reports/N6OapMZATf-zAzHjpa9Wcw/a37075177w102798190p106879314/%3F_u.dateOption%3Dlast7days%26454-table.plotKeys%3D%5B%5D%26454-table.rowStart%3D0%26454-table.rowCount%3D250/
  const rawCsv = fs.readFileSync(__dirname + '/metamaskGaq.csv', 'utf8')
  const result = parseCsv.parse(rawCsv, {
    skip_empty_lines: true,
    comment: '#',
    columns: true,
  }).map(row => row.Source).map(punycode.toASCII)
  return result
}

// 2024-05-08: harrydenley: we also allow ipfs CID blocking
function testListOnlyIncludesDomains (t, domains) {
  domains.forEach((domain) => {
    // If the entry is an IPFS CID, then pass it
    if(domain.match(ipfsCidRegex())) {
      return true;
    }

    if (domain.includes('/')) {
      t.fail('should be valid domain, not path')
    }
    try {
      const url = new URL(`https://${domain}`)
      t.equal(url.hostname, domain, `parsed domain name should match hostname`)
    } catch (err) {
      t.fail(`should only be valid domain, saw '${domain}'\n:${err.message}`)
    }
  })
}

function testListIsPunycode (t, list) {
  list.forEach((domain) => {
    t.equals(domain, punycode.toASCII(domain), `domain '${domain}' is encoded in punycode`)
  })
}

function testListDoesntContainRepeats (t, list) {
  const clone = new Set(list);
  if (clone.size === list.length) {
    return;
  }
  
  for (const item of list) {
    if (clone.has(item)) {
      clone.delete(item);
    } else {
      t.fail(`domain ${item} is duplicated. Domains can only appear in the list once`);
    }
  }
}

function testListIsContained (t, needles, stack) {
  needles.forEach((domain) => {
    if (!stack.includes(domain)) {
      t.fail(`${domain} in fuzzylist but not present in allowlist`, domain)
    }
  });
}

function testListNoConflictingEntries (t, config) {
  const allowlistSet = new Set(config['whitelist']);
  const blocklistSet = new Set(config['blacklist']);

  const intersection = Array.from(allowlistSet).filter(v => blocklistSet.has(v));

  for (const item of intersection) {
    t.fail(`domain ${item} appears on both the allowlist and blocklist`);
  }
}

async function loadRemoteJson (url) {
  const res = await needle('get', url).catch(err => {
    throw new Error(`Trouble loading list at "${url}":\n${err.stack}`)
  })
  if (res.statusCode !== 200) {
    throw new Error(`HTTP status ${res.statusCode} for list at "${url}":\n${res.body}`)
  }
  const result = JSON.parse(res.body)
  return result
}

module.exports = {
  formatHostnameToUrl,
  loadMetamaskGaq,
  loadRemoteJson,
  testListDoesntContainRepeats,
  testListIsContained,
  testListIsPunycode,
  testListNoConflictingEntries,
  testListOnlyIncludesDomains,
}
