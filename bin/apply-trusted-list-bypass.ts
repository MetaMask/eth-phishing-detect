#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { detectFalsePositives, parseTrustedListBypass } from "../test/trusted-list-utils.js";
import { Config } from "../src/types.js";

const TRUSTED_LIST_IDS = ["tranco", "coinmarketcap", "snapsregistry", "coingecko", "dapps"];
const COMMANDS = new Set(["/skip-trusted-lists", "skip trusted lists"]);

const policyRoot = path.dirname(__dirname);
const targetRoot = process.env.TRUSTED_LIST_BYPASS_TARGET || policyRoot;
const resourcesDir = path.join(targetRoot, "test", "resources");
const bypassPath = path.join(resourcesDir, "trusted-list-bypass.txt");

const readJson = async <T>(filePath: string): Promise<T> => {
    return JSON.parse(await readFile(filePath, { encoding: "utf-8" })) as T;
};

const normalizeHandle = (handle: string): string => {
    return handle.replace(/^@/u, "").toLowerCase();
};

const readExistingBypass = async (): Promise<string> => {
    try {
        return await readFile(bypassPath, { encoding: "utf-8" });
    } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
            throw error;
        }

        return [
            "# These domains are intentionally blocklisted even though they appear on a trusted comparison list.",
            "# Add evidence or a short reason after the domain when possible.",
            "",
        ].join("\n");
    }
};

const getCommand = (): string => {
    const firstLine = (process.env.TRUSTED_LIST_BYPASS_COMMENT || "").trim().split(/\r?\n/u)[0]?.trim() || "";
    const normalizedFirstLine = firstLine.toLowerCase();

    if (normalizedFirstLine.startsWith("/skip-trusted-lists")) {
        return "/skip-trusted-lists";
    }

    return normalizedFirstLine;
};

const getApprovedBy = (): string => {
    const approvedBy = process.env.TRUSTED_LIST_BYPASS_APPROVED_BY;
    if (!approvedBy) {
        throw new Error("TRUSTED_LIST_BYPASS_APPROVED_BY must be set");
    }

    return normalizeHandle(approvedBy);
};

const getPrNumber = (): string => {
    const prNumber = process.env.TRUSTED_LIST_BYPASS_PR_NUMBER;
    if (!prNumber) {
        throw new Error("TRUSTED_LIST_BYPASS_PR_NUMBER must be set");
    }

    return prNumber;
};

const assertCommand = () => {
    const command = getCommand();
    if (!COMMANDS.has(command)) {
        throw new Error(`Unsupported trusted-list bypass command: ${command}`);
    }
};

const assertApprovedReviewer = async (approvedBy: string) => {
    const reviewers = await readJson<string[]>(path.join(policyRoot, ".github", "trusted-list-bypass-reviewers.json"));
    const normalizedReviewers = new Set(reviewers.map(normalizeHandle));

    if (!normalizedReviewers.has(approvedBy)) {
        throw new Error(`@${approvedBy} is not approved to apply trusted-list bypasses`);
    }
};

const findBypassableEntries = async (config: Config, bypass: Set<string>): Promise<string[]> => {
    const entries = new Set<string>();

    for (const listId of TRUSTED_LIST_IDS) {
        const contents = await readFile(path.join(resourcesDir, `${listId}.txt`), { encoding: "utf-8" });
        const comparisonList = new Set(contents.split("\n"));
        const falsePositives = detectFalsePositives(config.blacklist!, comparisonList, bypass);

        for (const entry of falsePositives) {
            const bypassWithEntry = new Set([...bypass, entry]);
            const remaining = detectFalsePositives(config.blacklist!, comparisonList, bypassWithEntry);

            if (!remaining.includes(entry)) {
                entries.add(entry);
            }
        }
    }

    return Array.from(entries).sort();
};

const appendBypasses = async (contents: string, entries: string[], approvedBy: string, prNumber: string) => {
    if (entries.length === 0) {
        console.log("No trusted-list bypass entries need to be added.");
        return;
    }

    const existing = parseTrustedListBypass(contents);
    const newEntries = entries.filter((entry) => !existing.has(entry));

    if (newEntries.length === 0) {
        console.log("All trusted-list bypass entries are already present.");
        return;
    }

    const lines = newEntries.map((entry) => `${entry} # trusted-list bypass approved by @${approvedBy} in PR #${prNumber}`);
    const nextContents = `${contents.trimEnd()}\n${lines.join("\n")}\n`;

    await writeFile(bypassPath, nextContents);
    console.log(`Added trusted-list bypass entries: ${newEntries.join(", ")}`);
};

const main = async () => {
    assertCommand();

    const approvedBy = getApprovedBy();
    const prNumber = getPrNumber();

    await assertApprovedReviewer(approvedBy);

    const [config, bypassContents] = await Promise.all([
        readJson<Config>(path.join(targetRoot, "src", "config.json")),
        readExistingBypass(),
    ]);

    const bypass = parseTrustedListBypass(bypassContents);
    const entries = await findBypassableEntries(config, bypass);

    await appendBypasses(bypassContents, entries, approvedBy, prNumber);
};

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
