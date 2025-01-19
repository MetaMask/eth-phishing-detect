import test, { Test } from "tape";
import punycode from "punycode/";
import { cleanAllowlist, cleanBlocklist } from "../src/clean-config.js";
import PhishingDetector from "../src/detector.js";
import { Config } from "../src/types.js";
import { parse } from 'tldts';
import { customTlds } from './custom-tlds.js';

export const testBlocklist = (t: Test, domains: string[], options: Config) => {
    const detector = new PhishingDetector(options);

    domains.forEach((domain) => {
        testDomainWithDetector(t, {
            domain: domain,
            type: options && Array.isArray(options) ? "blocklist" : "blacklist",
            expected: true,
            detector,
        });
    });
};

export const testAllowlist = (t, domains, options) => {
    const detector = new PhishingDetector(options);

    domains.forEach((domain) => {
        testDomainWithDetector(t, {
            domain: domain,
            type: options && Array.isArray(options) ? "allowlist" : "whitelist",
            expected: false,
            detector,
        });
    });
};

export const testFuzzylist = (t, domains, options) => {
    const detector = new PhishingDetector(options);

    domains.forEach((domain) => {
        testDomainWithDetector(t, {
            domain: domain,
            type: "fuzzy",
            expected: true,
            detector,
        });
    });
};

export const testListOnlyIncludesDomains = (t: Test, domains: string[]) => {
    const failed = domains.filter((domain) => {
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
};

export const testListIsPunycode = (t: Test, list: string[]) => {
    const failed = list.filter((domain) => {
        const asciiDomain = punycode.toASCII(domain);
        return domain !== asciiDomain;
    });

    t.equal(failed.length, 0, `domains must be encoded using punycode: ${failed}`);
};

export const testListDoesntContainRepeats = (t: Test, list: string[]) => {
    const clone = new Set(list);
    if (clone.size === list.length) {
        t.pass("no duplicates found");
        return;
    }

    const duplicates = list.filter((domain) => {
        if (clone.has(domain)) {
            clone.delete(domain);
            return false;
        }

        return true;
    });

    t.equal(duplicates.length, 0, `domains must not appear in the list more than once: ${duplicates}`);
};

export const testListIsContained = (t, needles, stack) => {
    needles.forEach((domain) => {
        if (!stack.includes(domain)) {
            t.fail(`${domain} in fuzzylist but not present in allowlist`, domain);
        }
    });
};

export const testListNoConflictingEntries = (t, config) => {
    const allowlistSet = new Set(config["whitelist"]);
    const blocklistSet = new Set(config["blacklist"]);

    const intersection = Array.from(allowlistSet).filter((v) => blocklistSet.has(v));

    for (const item of intersection) {
        t.fail(`domain ${item} appears on both the allowlist and blocklist`);
    }
};

export const testListNoBlocklistRedundancies = (t, config) => {
    const cleanConfig = cleanBlocklist(config);
    t.ok(
        cleanConfig.blacklist!.length === config.blacklist.length,
        `blocklist contains ${config.blacklist.length - cleanConfig.blacklist!.length} redundant entries. run 'yarn clean:blocklist'.`,
    );
};

export const testListNoAllowlistRedundancies = (t, config) => {
    const cleanConfig = cleanAllowlist(config);
    t.ok(
        cleanConfig.whitelist!.length === config.whitelist.length,
        `allowlist contains ${config.whitelist.length - cleanConfig.whitelist!.length} redundant entries. run 'yarn clean:allowlist'.`,
    );
};

export const testNoMatch = (t, domains, options) => {
    const detector = new PhishingDetector(options);

    domains.forEach((domain) => {
        testDomainWithDetector(t, {
            domain: domain,
            type: "all",
            expected: false,
            detector,
        });
    });
};

export const testAnyType = (t, expected, domains, options) => {
    const detector = new PhishingDetector(options);

    domains.forEach((domain) => {
        testDomainWithDetector(t, {
            domain: domain,
            expected,
            detector,
        });
    });
};

type TestParams = {
    domain: string;
    name?: string;
    type?: string;
    version?: string;
    options?: any;
    detector: any;
    expected: any;
};

export const testDomain = (t, { domain, name, type, expected, options, version }: TestParams) => {
    const detector = new PhishingDetector(options);
    testDomainWithDetector(t, { domain, name, type, expected, detector, version });
};

export const testDomainWithDetector = (t: Test, { domain, name, type, expected, detector, version }: TestParams) => {
    const value = detector.check(domain);
    // log fuzzy match for debugging
    // if (value.type === 'fuzzy') {
    //   t.comment(`"${domain}" fuzzy matches against "${value.match}"`)
    // }
    // enforcing type is optional
    if (type) {
        t.equal(value.type, type, `type: "${domain}" should be "${type}"`);
    }
    if (name) {
        t.equal(value.name, name, `name: "${domain}" should return result from config "${name}"`);
    }
    if (version) {
        t.equal(value.version, version, `version: "${domain}" should return result from config version '${version}'`);
    }
    // enforcing result is required
    t.equal(value.result, expected, `result: "${domain}" should be match "${expected}"`);
};

type CustomParseResult = {
    domain: string | null;
    subdomain: string | null;
    publicSuffix: string | null;
};

// Create a wrapper function for PSL parsing
export function parseDomainWithCustomPSL(domain: string): CustomParseResult {
    // Check if the domain ends with any custom suffix
    const customSuffix = customTlds.find(suffix => domain === suffix || domain.endsWith('.' + suffix));

    if (customSuffix) {
        const parts = domain.split('.');
        const suffixParts = customSuffix.split('.');
        const domainParts = parts.slice(0, parts.length - suffixParts.length);
        const mainDomain = domainParts.length > 0 ? domainParts.join('.') : '';

        return {
            domain: mainDomain ? `${mainDomain}.${customSuffix}` : customSuffix,
            subdomain: mainDomain,
            publicSuffix: customSuffix,
        };
    }
    // Fallback to tldts parse
    const parsedDomain = parse(domain, {
        allowPrivateDomains: true,
    });
    return {
        domain: parsedDomain.domain,
        subdomain: parsedDomain.subdomain,
        publicSuffix: parsedDomain.publicSuffix,
    }
};

test("parseDomainWithCustomPSL", (t) => {
    const testCases = [
        {
            domain: 'app.gitbook.io',
            expected: {
                domain: 'app.gitbook.io',
                subdomain: 'app',
                publicSuffix: 'gitbook.io',
            },
            description: 'Subdomain should match custom TLD gitbook.io'
        },
        {
            domain: 'test.app.gitbook.io',
            expected: {
                domain: 'test.app.gitbook.io',
                subdomain: 'test.app',
                publicSuffix: 'gitbook.io',
            },
            description: 'Subdomain should match custom TLD gitbook.io with multiple subdomains'
        },
        {
            domain: 'gitbook.io',
            expected: {
                domain: 'gitbook.io',
                subdomain: '',
                publicSuffix: 'gitbook.io',
            },
            description: 'Exact match for custom TLD gitbook.io with no subdomain'
        },
        {
            domain: 'metamask-gitbook.io',
            expected: {
                domain: 'metamask-gitbook.io',
                subdomain: '',
                publicSuffix: 'io',
            },
            description: 'No match for custom TLD, fallback expected'
        },
        {
            domain: 'app.mypinata.cloud',
            expected: {
                domain: 'app.mypinata.cloud',
                subdomain: 'app',
                publicSuffix: 'mypinata.cloud',
            },
            description: 'Subdomain should match custom TLD mypinata.cloud'
        },
        {
            domain: 'mypinata.cloud',
            expected: {
                domain: 'mypinata.cloud',
                subdomain: '',
                publicSuffix: 'mypinata.cloud',
            },
            description: 'Exact match for custom TLD mypinata.cloud with no subdomain'
        },
        {
            domain: 'example.com',
            expected: {
                domain: 'example.com',
                subdomain: '',
                publicSuffix: 'com',
            },
            description: 'Fallback to tldts for standard TLD .com'
        },
        {
            domain: 'sub.example.com',
            expected: {
                domain: 'example.com',
                subdomain: 'sub',
                publicSuffix: 'com',
            },
            description: 'Fallback to tldts for standard TLD .com plus subdomain'
        },
        {
            domain: 'sub.gitbook.example.com',
            expected: {
                domain: 'example.com',
                subdomain: 'sub.gitbook',
                publicSuffix: 'com',
            },
            description: 'Fallback to tldts for standard TLD .com plus multiple subdomain'
        }
    ];

    testCases.forEach(({ domain, expected, description }) => {
        t.test(description, (st) => {
            const result = parseDomainWithCustomPSL(domain);

            st.equal(result.domain, expected.domain, 'Correct domain');
            st.equal(result.subdomain, expected.subdomain, 'Correct subdomain');
            st.equal(result.publicSuffix, expected.publicSuffix, 'Correct public suffix');

            st.end();
        });
    });

    t.end();
});

export function detectFalsePositives(blocklist: string[], comparisonList: Set<string>, bypassList: Set<string>): string[] {
    const blocked = blocklist.filter(hostname => {
        const parsedDomain = parseDomainWithCustomPSL(hostname);
        return comparisonList.has(parsedDomain.domain || "") && !bypassList.has(hostname);
    });

    return blocked;
}

test("detectFalsePositives", (t) => {
    const testCases = [
        {
            mockBlocklist: ['examplescam.com', 'scamsite.xyz'],
            mockComparisonList: new Set<string>(['google.com', 'youtube.com']),
            mockBypassList: new Set<string>(['mystrikingly.com']),
            expectedLength: 0,
            description: 'Happy path - no URLs exist on the comparison list',
        },
        {
            mockBlocklist: ['auth.magic.link'],
            mockComparisonList: new Set<string>(['magic.link']),
            mockBypassList: new Set<string>(),
            expectedLength: 1,
            description: 'Should parse correctly to prevent additions that exist on comparison list',
        },
        {
            mockBlocklist: ['gitbook.io'],
            mockComparisonList: new Set<string>(['google.com', 'gitbook.io']),
            mockBypassList: new Set<string>(),
            expectedLength: 1,
            description: 'Hosting providers are prevented from being added',
        },
        {
            mockBlocklist: ['scam.netlify.app'],
            mockComparisonList: new Set<string>(['google.com', 'netlify.app']),
            mockBypassList: new Set<string>(),
            expectedLength: 0,
            description: 'Hosting providers with a real PSL are parsed correctly and skipped',
        },
        {
            mockBlocklist: ['scam.gitbook.io'],
            mockComparisonList: new Set<string>(['google.com', 'gitbook.io']),
            mockBypassList: new Set<string>(),
            expectedLength: 0,
            description: 'Hosting providers with a custom PSL are parsed correctly and skipped',
        },
        {
            mockBlocklist: ['scam.com'],
            mockComparisonList: new Set<string>(['scam.com']),
            mockBypassList: new Set<string>(['scam.com']),
            expectedLength: 0,
            description: 'Bypass list works when a potential scam exists on tranco',
        },
    ];

    testCases.forEach(({ mockBlocklist, mockComparisonList, mockBypassList, expectedLength, description }) => {
        t.test(description, (st) => {
            const result = detectFalsePositives(mockBlocklist, mockComparisonList, mockBypassList);

            st.equal(result.length, expectedLength, 'Correct length');
            st.end();
        });
    });

    t.end();
});
