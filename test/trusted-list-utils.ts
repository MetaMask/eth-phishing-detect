export { detectFalsePositives, parseDomainWithCustomPSL } from "./trusted-list-detection.js";

export function parseTrustedListBypass(contents: string): Set<string> {
    return new Set(
        contents
            .split(/\r?\n/u)
            .map((line) => line.replace(/^\s*#.*$/u, "").replace(/\s+#.*$/u, "").trim())
            .filter(Boolean),
    );
}
