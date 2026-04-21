import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "tape";
import { Config } from "../src/types";
import { detectFalsePositives, parseTrustedListBypass } from "./trusted-list-utils.js";

const resourcesDir = path.join(__dirname, "resources");

export const runTests = (config: Config) => {
    const testList = (listId: string) => {
        test(`ensure no trusted-list domains are blocked: ${listId}`, async (t) => {
            const [contents, bypassContents] = await Promise.all([
                readFile(path.join(resourcesDir, `${listId}.txt`), { encoding: "utf-8" }),
                readFile(path.join(resourcesDir, "trusted-list-bypass.txt"), { encoding: "utf-8" }),
            ]);

            const domains = new Set(contents.split("\n"));
            const bypass = parseTrustedListBypass(bypassContents);

            const falsePositives = detectFalsePositives(config.blacklist!, domains, bypass);

            t.equal(falsePositives.length, 0, `The following domains should not be blocked: ${falsePositives}`);

            t.end();
        });
    };

    testList("tranco");
    testList("coinmarketcap");
    testList("snapsregistry");
    testList("coingecko");
    testList("dapps");
};
