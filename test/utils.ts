import test, { Test } from "tape";
import punycode from "punycode/";
import { cleanAllowlist, cleanBlocklist } from "../src/clean-config.js";
import PhishingDetector from "../src/detector.js";
import { Config } from "../src/types.js";
import { parse } from 'tldts';
import { customTlds } from './custom-tlds.js';
import { PATH_REQUIRED_DOMAINS } from './path-enabled-domains.js';

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
        try {
            // For entries that contain paths, validate as full URLs
            if (domain.includes("/")) {
                const url = new URL(`https://${domain}`);
                // Ensure the hostname + pathname matches the original domain
                const expectedPath = domain.substring(domain.indexOf("/"));
                if (url.pathname !== expectedPath) return true;
                // Ensure the hostname part is valid
                const hostname = domain.substring(0, domain.indexOf("/"));
                if (url.hostname !== hostname) return true;
            } else {
                // For entries without paths, validate as domains only
                const url = new URL(`https://${domain}`);
                if (url.hostname !== domain) return true;
                
                // Check if this domain requires a path
                if (PATH_REQUIRED_DOMAINS.includes(domain)) {
                    return true; // Fail validation - this domain requires a path
                }
            }
        } catch {
            return true;
        }

        return false;
    });

    t.equal(failed.length, 0, `list must only contain domains or valid URLs with paths. Domains ${PATH_REQUIRED_DOMAINS.join(', ')} require paths: ${failed}`);
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
        // Extract the hostname from URLs that contain paths
        let domainToCheck = hostname;
        let hasPath = hostname.includes("/");
        
        if (hasPath) {
            try {
                const url = new URL(`https://${hostname}`);
                domainToCheck = url.hostname;
            } catch {
                // If URL parsing fails, use the original hostname
                domainToCheck = hostname.substring(0, hostname.indexOf("/"));
            }
            
            // If hostname has a path but is not in PATH_REQUIRED_DOMAINS, it's a false positive
            if (!PATH_REQUIRED_DOMAINS.includes(domainToCheck)) {
                return true;
            }

            return false;
        }
        
        const parsedDomain = parseDomainWithCustomPSL(domainToCheck);
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
        {
            mockBlocklist: ['sites.google.com/view/malicious'],
            mockComparisonList: new Set<string>(['google.com', 'sites.google.com']),
            mockBypassList: new Set<string>(),
            expectedLength: 0,
            description: 'URLs with paths should not be detected as false positives when hostname is on comparison list',
        },
        {
            mockBlocklist: ['example.com/malicious/path'],
            mockComparisonList: new Set<string>(['different.com']),
            mockBypassList: new Set<string>(),
            expectedLength: 1,
            description: 'URLs with paths should be detected as false positive when hostname is not in PATH_REQUIRED_DOMAINS',
        },
        {
            mockBlocklist: ['sites.google.com/view/malicious'],
            mockComparisonList: new Set<string>(['sites.google.com']),
            mockBypassList: new Set<string>(['sites.google.com/view/malicious']),
            expectedLength: 0,
            description: 'URLs with paths should respect bypass list with full URL',
        },
        {
            mockBlocklist: ['twitter.com/malicious/account'],
            mockComparisonList: new Set<string>(['different.com', 'twitter.com']),
            mockBypassList: new Set<string>(),
            expectedLength: 0,
            description: 'URLs with paths should not be detected as false positive when hostname is in PATH_REQUIRED_DOMAINS',
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

test("testListOnlyIncludesDomains with paths", (t) => {
    const testCases = [
        {
            domains: ['example.com', 'google.com'],
            expectedFailures: 0,
            description: 'should pass with regular domains'
        },
        {
            domains: ['sites.google.com/view/malicious', 'example.com/path/to/page'],
            expectedFailures: 0,
            description: 'should pass with valid URLs containing paths'
        },
        {
            domains: ['invalid domain with spaces', 'another invalid'],
            expectedFailures: 2,
            description: 'should fail with invalid domains'
        },
        {
            domains: ['example.com', 'sites.google.com/view/malicious', 'invalid domain'],
            expectedFailures: 1,
            description: 'should fail only with invalid entries'
        },
        {
            domains: ['sites.google.com'],
            expectedFailures: 1,
            description: 'should fail when path-required domain has no path'
        },
        {
            domains: ['cdpn.io', 'twitter.com', 'x.com'],
            expectedFailures: 3,
            description: 'should fail when all path-required domains have no paths'
        },
        {
            domains: ['cdpn.io/something', 'twitter.com/user/status', 'x.com/post'],
            expectedFailures: 0,
            description: 'should pass when path-required domains have paths'
        },
        {
            domains: ['example.com', 'cdpn.io', 'sites.google.com/view/page'],
            expectedFailures: 1,
            description: 'should fail only path-required domain without path'
        }
    ];

    testCases.forEach(({ domains, expectedFailures, description }) => {
        t.test(description, (st) => {
            let actualFailures = 0;
            // Mock the t.equal function to count failures
            const mockTest = {
                equal: (actual: number, expected: number, message: string) => {
                    if (actual !== expected) {
                        actualFailures = actual;
                    }
                }
            };
            
            testListOnlyIncludesDomains(mockTest as any, domains);
            st.equal(actualFailures, expectedFailures, `Expected ${expectedFailures} failures, got ${actualFailures}`);
            st.end();
        });
    });

    t.end();
});
