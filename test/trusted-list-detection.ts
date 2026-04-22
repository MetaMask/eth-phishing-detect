import { parse } from "tldts";
import { customTlds } from "./custom-tlds.js";
import { PATH_REQUIRED_DOMAINS } from "./path-enabled-domains.js";

type CustomParseResult = {
    domain: string | null;
    subdomain: string | null;
    publicSuffix: string | null;
};

export function parseDomainWithCustomPSL(domain: string): CustomParseResult {
    const customSuffix = customTlds.find((suffix) => domain === suffix || domain.endsWith("." + suffix));

    if (customSuffix) {
        const parts = domain.split(".");
        const suffixParts = customSuffix.split(".");
        const domainParts = parts.slice(0, parts.length - suffixParts.length);
        const mainDomain = domainParts.length > 0 ? domainParts.join(".") : "";

        return {
            domain: mainDomain ? `${mainDomain}.${customSuffix}` : customSuffix,
            subdomain: mainDomain,
            publicSuffix: customSuffix,
        };
    }

    const parsedDomain = parse(domain, {
        allowPrivateDomains: true,
    });

    return {
        domain: parsedDomain.domain,
        subdomain: parsedDomain.subdomain,
        publicSuffix: parsedDomain.publicSuffix,
    };
}

export function extractHostname(domainWithPath: string): string {
    try {
        const url = new URL(`https://${domainWithPath}`);
        return url.hostname;
    } catch {
        return domainWithPath.substring(0, domainWithPath.indexOf("/"));
    }
}

function isInvalidPathDomain(hostname: string): boolean {
    const hasPath = hostname.includes("/");
    if (!hasPath) return false;

    const domainPart = extractHostname(hostname);
    return !PATH_REQUIRED_DOMAINS.includes(domainPart);
}

function isOnComparisonListNotBypassed(
    hostname: string,
    comparisonList: Set<string>,
    bypassList: Set<string>,
): boolean {
    if (bypassList.has(hostname)) return false;

    // Only check domains without paths - domains with paths are allowed to be blocked specifically.
    if (hostname.includes("/")) return false;

    const parsedDomain = parseDomainWithCustomPSL(hostname);
    return comparisonList.has(parsedDomain.domain || "");
}

export function detectFalsePositives(
    blocklist: string[],
    comparisonList: Set<string>,
    bypassList: Set<string>,
): string[] {
    return blocklist.filter((hostname) => {
        if (isInvalidPathDomain(hostname)) {
            return true;
        }

        if (isOnComparisonListNotBypassed(hostname, comparisonList, bypassList)) {
            return true;
        }

        return false;
    });
}
