import test from "tape";
import { cleanAllowlist, cleanBlocklist } from "../src/clean-config.js";

export const runTests = () => {
    test("produces identical copy of empty config", (t) => {
        const validConfig = {
            version: 2,
            tolerance: 5,
            fuzzylist: [],
            whitelist: [],
            blacklist: [],
        };
        t.deepEqual(cleanAllowlist(validConfig), validConfig);
        t.deepEqual(cleanBlocklist(validConfig), validConfig);
        t.end();
    });
    test("produces identical copy for config without duplicates", (t) => {
        const validConfig = {
            version: 2,
            tolerance: 5,
            fuzzylist: ["bar.localhost"],
            whitelist: ["foo.bar.localhost", "foo.example.com", "foo.localhost"],
            blacklist: ["example.com"],
        };
        t.deepEqual(cleanAllowlist(validConfig), validConfig);
        t.deepEqual(cleanBlocklist(validConfig), validConfig);
        t.end();
    });
    test("removes duplicate", (t) => {
        const allowInput = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["foo.example.com", "foo.example.com"],
            blacklist: ["example.com"],
        };
        const allowExpected = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["foo.example.com"],
            blacklist: ["example.com"],
        };
        const blockInput = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["foo.example.com", "foo.example.com"],
            blacklist: ["example.com", "example.com"],
        };
        const blockExpected = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["foo.example.com", "foo.example.com"],
            blacklist: ["example.com"],
        };
        t.deepEqual(cleanAllowlist(allowInput), allowExpected);
        t.deepEqual(cleanBlocklist(blockInput), blockExpected);
        t.end();
    });
    test("cleanBlocklist removes subdomain of domain already present", (t) => {
        const input = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["foo.example.com"],
            blacklist: ["bar.example.com", "example.com"],
        };
        const expected = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["foo.example.com"],
            blacklist: ["example.com"],
        };
        t.deepEqual(cleanBlocklist(input), expected);
        t.end();
    });
    test("cleanBlocklist keeps domain despite matching fuzzylist", (t) => {
        const input = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["foo.example.com"],
            blacklist: ["b4r.localhost"],
        };
        const expected = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["foo.example.com"],
            blacklist: ["b4r.localhost"],
        };
        t.deepEqual(cleanBlocklist(input), expected);
        t.end();
    });
    test("cleanBlocklist normalizes ipfs subpath gateway links to CID", (t) => {
        const input = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["foo.example.com"],
            blacklist: [
                "https://ipfs.io/ipfs/bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/wiki/Vincent_van_Gogh.html",
                "https://ipfs.io/ipfs/bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq",
                "https://ipfs.io/ipfs/bafybeia7cu2axyyxsarmaemvlpdpofa4q23lzpltbl4jbrnfixdn573h4y",
            ],
        };
        const expected = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["foo.example.com"],
            blacklist: [
                "bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq",
                "bafybeia7cu2axyyxsarmaemvlpdpofa4q23lzpltbl4jbrnfixdn573h4y",
            ],
        };
        t.deepEqual(cleanBlocklist(input), expected);
        t.end();
    });
    test("cleanBlocklist normalizes ipfs subdomain gateway links to CID", (t) => {
        const input = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["foo.example.com"],
            blacklist: [
                "bafybeia7cu2axyyxsarmaemvlpdpofa4q23lzpltbl4jbrnfixdn573h4y.ipfs.dweb.link",
                "bafybeia7cu2axyyxsarmaemvlpdpofa4q23lzpltbl4jbrnfixdn573h4y.ipfs.cf-ipfs.com",
                "bafybeifktatrljxysseq6w7kz55v2kgmy3krs7rqh4xh7uu6kv2rcfq6dy.ipfs.dweb.link",
            ],
        };
        const expected = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["foo.example.com"],
            blacklist: [
                "bafybeia7cu2axyyxsarmaemvlpdpofa4q23lzpltbl4jbrnfixdn573h4y",
                "bafybeifktatrljxysseq6w7kz55v2kgmy3krs7rqh4xh7uu6kv2rcfq6dy",
            ],
        };
        t.deepEqual(cleanBlocklist(input), expected);
        t.end();
    });
    // test('cleanAllowlist removes domain not matched in other lists', (t) => {
    //     const input = {
    //         version: 2,
    //         tolerance: 1,
    //         fuzzylist: [
    //             'bar.localhost',
    //         ],
    //         whitelist: [
    //             'b44r.localhost',
    //         ],
    //         blacklist: [
    //             'foo.example.com',
    //         ],
    //     };
    //     const expected = {
    //         version: 2,
    //         tolerance: 1,
    //         fuzzylist: [
    //             'bar.localhost',
    //         ],
    //         whitelist: [
    //         ],
    //         blacklist: [
    //             'foo.example.com',
    //         ],
    //     };
    //     t.deepEqual(cleanAllowlist(input), expected);
    //     t.end()
    // });
    test("cleanAllowlist keeps domain matching fuzzylist", (t) => {
        const input = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["b44r.localhost"],
            blacklist: ["foo.example.com"],
        };
        const expected = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["b44r.localhost"],
            blacklist: ["foo.example.com"],
        };
        t.deepEqual(cleanAllowlist(input), expected);
        t.end();
    });
    test("cleanAllowlist keeps subdomain of domain present in blocklist", (t) => {
        const input = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["bar.foo.example.com"],
            blacklist: ["foo.example.com"],
        };
        const expected = {
            version: 2,
            tolerance: 2,
            fuzzylist: ["bar.localhost"],
            whitelist: ["bar.foo.example.com"],
            blacklist: ["foo.example.com"],
        };
        t.deepEqual(cleanAllowlist(input), expected);
        t.end();
    });
};
