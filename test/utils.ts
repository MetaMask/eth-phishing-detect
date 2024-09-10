import { Test } from 'tape';
import punycode from 'punycode/'
import { cleanAllowlist, cleanBlocklist } from '../src/clean-config.js';
import PhishingDetector from '../src/detector.js';

export const testBlocklist = (t: Test, domains: string[], options) => {
  const detector = new PhishingDetector(options);

  domains.forEach((domain) => {
    testDomainWithDetector(t, {
      domain: domain,
      type: options && Array.isArray(options) ? 'blocklist' : 'blacklist',
      expected: true,
      detector,
    })
  })
}

export const testAllowlist = (t, domains, options) => {
  const detector = new PhishingDetector(options);

  domains.forEach((domain) => {
    testDomainWithDetector(t, {
      domain: domain,
      type: options && Array.isArray(options) ? 'allowlist' : 'whitelist',
      expected: false,
      detector,
    })
  })
}

export const testFuzzylist = (t, domains, options) => {
  const detector = new PhishingDetector(options);

  domains.forEach((domain) => {
    testDomainWithDetector(t, {
      domain: domain,
      type: 'fuzzy',
      expected: true,
      detector,
    })
  })
}

export const testListOnlyIncludesDomains = (t: Test, domains: string[]) => {
  const failed = domains.filter(domain => {
    if (domain.includes("/")) return true;

    try {
      const url = new URL(`https://${domain}`);
      if (url.hostname !== domain) return true;

    } catch {
      return true;
    }

    return false;
  });

  t.equal(failed.length, 0, `list must only contain domains: ${failed}`);
}

export const testListIsPunycode = (t: Test, list: string[]) => {
  const failed = list.filter(domain => {
    const asciiDomain = punycode.toASCII(domain);
    return domain !== asciiDomain;
  });

  t.equal(failed.length, 0, `domains must be encoded using punycode: ${failed}`);
}

export const testListDoesntContainRepeats = (t: Test, list: string[]) => {
  const clone = new Set(list);
  if (clone.size === list.length) {
    t.pass('no duplicates found');
    return;
  }

  const duplicates = list.filter(domain => {
    if (clone.has(domain)) {
      clone.delete(domain);
      return false;
    }

    return true;
  });

  t.equal(duplicates.length, 0, `domains must not appear in the list more than once: ${duplicates}`);
}

export const testListIsContained = (t, needles, stack) => {
  needles.forEach((domain) => {
    if (!stack.includes(domain)) {
      t.fail(`${domain} in fuzzylist but not present in allowlist`, domain)
    }
  });
}

export const testListNoConflictingEntries = (t, config) => {
  const allowlistSet = new Set(config['whitelist']);
  const blocklistSet = new Set(config['blacklist']);

  const intersection = Array.from(allowlistSet).filter(v => blocklistSet.has(v));

  for (const item of intersection) {
    t.fail(`domain ${item} appears on both the allowlist and blocklist`);
  }
}

export const testListNoBlocklistRedundancies = (t, config) => {
  const cleanConfig = cleanBlocklist(config)
  t.ok(cleanConfig.blacklist.length === config.blacklist.length, `blocklist contains ${config.blacklist.length - cleanConfig.blacklist.length} redundant entries. run 'yarn clean:blocklist'.`)
}

export const testListNoAllowlistRedundancies = (t, config) => {
  const cleanConfig = cleanAllowlist(config)
  t.ok(cleanConfig.whitelist.length === config.whitelist.length, `allowlist contains ${config.whitelist.length - cleanConfig.whitelist.length} redundant entries. run 'yarn clean:allowlist'.`)
}

export const testNoMatch = (t, domains, options) => {
  const detector = new PhishingDetector(options);

  domains.forEach((domain) => {
    testDomainWithDetector(t, {
      domain: domain,
      type: 'all',
      expected: false,
      detector,
    })
  })
}

export const testAnyType = (t, expected, domains, options) => {
  const detector = new PhishingDetector(options);

  domains.forEach((domain) => {
    testDomainWithDetector(t, {
      domain: domain,
      expected,
      detector,
    })
  })
}

type TestParams = {
  domain: string;
  name?: string;
  type?: string;
  version?: string;
  options?: any;
  detector: any;
  expected: any;
}

export const testDomain = (t, { domain, name, type, expected, options, version }: TestParams) => {
  const detector = new PhishingDetector(options)
  testDomainWithDetector(t, { domain, name, type, expected, detector, version })
}

export const testDomainWithDetector = (t, { domain, name, type, expected, detector, version }: TestParams) => {
  const value = detector.check(domain)
  // log fuzzy match for debugging
  // if (value.type === 'fuzzy') {
  //   t.comment(`"${domain}" fuzzy matches against "${value.match}"`)
  // }
  // enforcing type is optional
  if (type) {
    t.equal(value.type, type, `type: "${domain}" should be "${type}"`)
  }
  if (name) {
    t.equal(value.name, name, `name: "${domain}" should return result from config "${name}"`)
  }
  if (version) {
    t.equal(value.version, version, `version: "${domain}" should return result from config version '${version}'`)
  }
  // enforcing result is required
  t.equal(value.result, expected, `result: "${domain}" should be match "${expected}"`)
}
