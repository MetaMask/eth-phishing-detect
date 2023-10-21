(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
const why = require('./why')

window.addEventListener('load', function() {
  document.querySelector('form').addEventListener('submit', (ev) => {
    ev.preventDefault()
    result.innerText = why(input.value)
  })
})


},{"./why":2}],2:[function(require,module,exports){
const PhishingDetector = require('../src/detector')

let phishing;
let detector;

fetch('https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json')
  .then(response => response.json())
  .then(data => {
    phishing = data;
    detector = new PhishingDetector(phishing);
  })
  .catch(error => console.error('Error:', error));

function why (domain) {
  if (!detector) {
    return 'Cannot answer, still loading list data...'
  }

  const reason = detector.check(domain)

  if (!reason.result) {
    return 'This domain is not blocked! No problem here.'
  }

  if (reason.type === 'fuzzy') {
    return `This domain was blocked for its similarity to ${reason.match}, a historical phishing target.`
  }

  if (reason.type === 'blacklist') {
    return `This domain was blocked because it has been explicitly identified as a malicious site.`
  }

  return `There was an issue identifying the reason for the block. The data is ${JSON.stringify(reason)}`
}

module.exports = why
},{"../src/detector":4}],3:[function(require,module,exports){
"use strict";
exports.__esModule = true;
exports.distance = exports.closest = void 0;
var peq = new Uint32Array(0x10000);
var myers_32 = function (a, b) {
    var n = a.length;
    var m = b.length;
    var lst = 1 << (n - 1);
    var pv = -1;
    var mv = 0;
    var sc = n;
    var i = n;
    while (i--) {
        peq[a.charCodeAt(i)] |= 1 << i;
    }
    for (i = 0; i < m; i++) {
        var eq = peq[b.charCodeAt(i)];
        var xv = eq | mv;
        eq |= ((eq & pv) + pv) ^ pv;
        mv |= ~(eq | pv);
        pv &= eq;
        if (mv & lst) {
            sc++;
        }
        if (pv & lst) {
            sc--;
        }
        mv = (mv << 1) | 1;
        pv = (pv << 1) | ~(xv | mv);
        mv &= xv;
    }
    i = n;
    while (i--) {
        peq[a.charCodeAt(i)] = 0;
    }
    return sc;
};
var myers_x = function (b, a) {
    var n = a.length;
    var m = b.length;
    var mhc = [];
    var phc = [];
    var hsize = Math.ceil(n / 32);
    var vsize = Math.ceil(m / 32);
    for (var i = 0; i < hsize; i++) {
        phc[i] = -1;
        mhc[i] = 0;
    }
    var j = 0;
    for (; j < vsize - 1; j++) {
        var mv_1 = 0;
        var pv_1 = -1;
        var start_1 = j * 32;
        var vlen_1 = Math.min(32, m) + start_1;
        for (var k = start_1; k < vlen_1; k++) {
            peq[b.charCodeAt(k)] |= 1 << k;
        }
        for (var i = 0; i < n; i++) {
            var eq = peq[a.charCodeAt(i)];
            var pb = (phc[(i / 32) | 0] >>> i) & 1;
            var mb = (mhc[(i / 32) | 0] >>> i) & 1;
            var xv = eq | mv_1;
            var xh = ((((eq | mb) & pv_1) + pv_1) ^ pv_1) | eq | mb;
            var ph = mv_1 | ~(xh | pv_1);
            var mh = pv_1 & xh;
            if ((ph >>> 31) ^ pb) {
                phc[(i / 32) | 0] ^= 1 << i;
            }
            if ((mh >>> 31) ^ mb) {
                mhc[(i / 32) | 0] ^= 1 << i;
            }
            ph = (ph << 1) | pb;
            mh = (mh << 1) | mb;
            pv_1 = mh | ~(xv | ph);
            mv_1 = ph & xv;
        }
        for (var k = start_1; k < vlen_1; k++) {
            peq[b.charCodeAt(k)] = 0;
        }
    }
    var mv = 0;
    var pv = -1;
    var start = j * 32;
    var vlen = Math.min(32, m - start) + start;
    for (var k = start; k < vlen; k++) {
        peq[b.charCodeAt(k)] |= 1 << k;
    }
    var score = m;
    for (var i = 0; i < n; i++) {
        var eq = peq[a.charCodeAt(i)];
        var pb = (phc[(i / 32) | 0] >>> i) & 1;
        var mb = (mhc[(i / 32) | 0] >>> i) & 1;
        var xv = eq | mv;
        var xh = ((((eq | mb) & pv) + pv) ^ pv) | eq | mb;
        var ph = mv | ~(xh | pv);
        var mh = pv & xh;
        score += (ph >>> (m - 1)) & 1;
        score -= (mh >>> (m - 1)) & 1;
        if ((ph >>> 31) ^ pb) {
            phc[(i / 32) | 0] ^= 1 << i;
        }
        if ((mh >>> 31) ^ mb) {
            mhc[(i / 32) | 0] ^= 1 << i;
        }
        ph = (ph << 1) | pb;
        mh = (mh << 1) | mb;
        pv = mh | ~(xv | ph);
        mv = ph & xv;
    }
    for (var k = start; k < vlen; k++) {
        peq[b.charCodeAt(k)] = 0;
    }
    return score;
};
var distance = function (a, b) {
    if (a.length < b.length) {
        var tmp = b;
        b = a;
        a = tmp;
    }
    if (b.length === 0) {
        return a.length;
    }
    if (a.length <= 32) {
        return myers_32(a, b);
    }
    return myers_x(a, b);
};
exports.distance = distance;
var closest = function (str, arr) {
    var min_distance = Infinity;
    var min_index = 0;
    for (var i = 0; i < arr.length; i++) {
        var dist = distance(str, arr[i]);
        if (dist < min_distance) {
            min_distance = dist;
            min_index = i;
        }
    }
    return arr[min_index];
};
exports.closest = closest;

},{}],4:[function(require,module,exports){
const { distance } = require('fastest-levenshtein')
const DEFAULT_TOLERANCE = 3

class PhishingDetector {

  /**
   * Construct a phishing detector, which can check whether origins are known
   * to be malicious or similar to common phishing targets.
   *
   * A list of configurations is accepted. Each origin checked is processed
   * using each configuration in sequence, so the order defines which
   * configurations take precedence.
   *
   * @param {LegacyPhishingDetectorConfiguration | PhishingDetectorConfiguration[]} opts - Phishing detection options
   */
  constructor (opts) {
    // recommended configuration
    if (Array.isArray(opts)) {
      this.configs = processConfigs(opts)
      this.legacyConfig = false
    // legacy configuration
    } else {
      this.configs = [{
        allowlist: processDomainList(opts.whitelist || []),
        blocklist: processDomainList(opts.blacklist || []),
        fuzzylist: processDomainList(opts.fuzzylist || []),
        tolerance: ('tolerance' in opts) ? opts.tolerance : DEFAULT_TOLERANCE
      }]
      this.legacyConfig = true
    }
  }

  check(domain) {
    const result = this._check(domain)

    if (this.legacyConfig) {
      let legacyType = result.type;
      if (legacyType === 'allowlist') {
        legacyType = 'whitelist'
      } else if (legacyType === 'blocklist') {
        legacyType = 'blacklist'
      }
      return {
        match: result.match,
        result: result.result,
        type: legacyType,
      }
    }
    return result
  }

  _check (domain) {
    let fqdn = domain.substring(domain.length - 1) === "."
      ? domain.slice(0, -1)
      : domain;

    const source = domainToParts(fqdn)

    for (const { allowlist, name, version } of this.configs) {
      // if source matches allowlist hostname (or subdomain thereof), PASS
      const allowlistMatch = matchPartsAgainstList(source, allowlist)
      if (allowlistMatch) {
        const match = domainPartsToDomain(allowlistMatch);
        return { match, name, result: false, type: 'allowlist', version }
      }
    }

    for (const { blocklist, fuzzylist, name, tolerance, version } of this.configs) {
      // if source matches blocklist hostname (or subdomain thereof), FAIL
      const blocklistMatch = matchPartsAgainstList(source, blocklist)
      if (blocklistMatch) {
        const match = domainPartsToDomain(blocklistMatch);
        return { match, name, result: true, type: 'blocklist', version }
      }

      if (tolerance > 0) {
        // check if near-match of whitelist domain, FAIL
        let fuzzyForm = domainPartsToFuzzyForm(source)
        // strip www
        fuzzyForm = fuzzyForm.replace(/^www\./, '')
        // check against fuzzylist
        const levenshteinMatched = fuzzylist.find((targetParts) => {
          const fuzzyTarget = domainPartsToFuzzyForm(targetParts)
          const dist = distance(fuzzyForm, fuzzyTarget)
          return dist <= tolerance
        })
        if (levenshteinMatched) {
          const match = domainPartsToDomain(levenshteinMatched)
          return { name, match, result: true, type: 'fuzzy', version }
        }
      }
    }

    // matched nothing, PASS
    return { result: false, type: 'all' }
  }

}

PhishingDetector.processDomainList = processDomainList
PhishingDetector.domainToParts = domainToParts
PhishingDetector.domainPartsToDomain = domainPartsToDomain
module.exports = PhishingDetector

// util

function processConfigs(configs = []) {
  return configs.map((config) => {
    validateConfig(config)
    return Object.assign({}, config, {
      allowlist: processDomainList(config.allowlist || []),
      blocklist: processDomainList(config.blocklist || []),
      fuzzylist: processDomainList(config.fuzzylist || []),
      tolerance: ('tolerance' in config) ? config.tolerance : DEFAULT_TOLERANCE
    })
  });
}

function validateConfig(config) {
  if (config === null || typeof config !== 'object') {
    throw new Error('Invalid config')
  }

  if (config.tolerance && !config.fuzzylist) {
    throw new Error('Fuzzylist tolerance provided without fuzzylist')
  }

  if (
    typeof config.name !== 'string' ||
    config.name === ''
  ) {
    throw new Error("Invalid config parameter: 'name'")
  }

  if (
    !['number', 'string'].includes(typeof config.version) ||
    config.version === ''
  ) {
    throw new Error("Invalid config parameter: 'version'")
  }
}

function processDomainList (list) {
  return list.map(domainToParts)
}

function domainToParts (domain) {
  try {
  return domain.split('.').reverse()
  } catch (e) {
    throw new Error(JSON.stringify(domain))
  }
}

function domainPartsToDomain(domainParts) {
  return domainParts.slice().reverse().join('.')
}

// for fuzzy search, drop TLD and re-stringify
function domainPartsToFuzzyForm(domainParts) {
  return domainParts.slice(1).reverse().join('.')
}

// match the target parts, ignoring extra subdomains on source
// returns parts for first found matching entry
//   source: [io, metamask, xyz]
//   target: [io, metamask]
//   result: PASS
function matchPartsAgainstList(source, list) {
  return list.find((target) => {
    // target domain has more parts than source, fail
    if (target.length > source.length) return false
    // source matches target or (is deeper subdomain)
    return target.every((part, index) => source[index] === part)
  })
}

},{"fastest-levenshtein":3}]},{},[1]);
