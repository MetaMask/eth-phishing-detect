#!/usr/bin/env node

import { parse } from 'csv-parse/sync';
import dotenv from 'dotenv';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';

dotenv.config({ path: `.env` });

type CoinMarketCapQuote = {
    price: number;
    market_cap: number;
}

type CoinMarketCapListing = {
    id: number;
    name: string;
    slug: string;
    quote: Record<string, CoinMarketCapQuote>;
}

type CoinMarketCapListingsResponse = {
    data: CoinMarketCapListing[];
}

type CoinMarketCapMetadataV2 = {
    id: number;
    name: string;
    symbol: string;
    slug: string;
    urls: {
        website: string[];
    };
}

type CoinMarketCapMetadataV2Response = {
    data: Record<string, CoinMarketCapMetadataV2>;
}

type Snap = {
    id: string;
    metadata: {
        name: string;
        author?: {
            name: string;
            website?: string;
        },
        website?: string;
    }
}

type SnapsRegistry = {
    verifiedSnaps: Record<string, Snap>;
};

type CoinGeckoExchangeV3 = {
    id: string;
    url: string;
}

type CoinGeckoExchangesV3Response = CoinGeckoExchangeV3[];

const resourcesDir = path.join(path.dirname(__dirname), 'test', 'resources');

const fetchTrancoList = async (): Promise<string[]> => {
    const latestListId = await fetch("https://tranco-list.eu/top-1m-id");
    if (latestListId.status !== 200) {
        throw new Error(`failed to fetch latest tranco list id: http ${latestListId.status}`);
    }

    const id = await latestListId.text();

    const trancoResponse = await fetch(`https://tranco-list.eu/download/${id}/200000`);
    if (trancoResponse.status !== 200) {
        throw new Error(`failed to fetch tranco list: http ${trancoResponse.status}`);
    }

    const records = parse(await trancoResponse.text(), {
        columns: ['rank', 'domain'],
    }) as { rank: string, domain: string }[];

    return records.map(record => record.domain);
};

const fetchCoinMarketCapList = async (apiKey: string): Promise<string[]> => {
    const latestListingsParams = new URLSearchParams({
        start: '1',
        limit: '5000',
        market_cap_min: '10000000',
        sort: 'market_cap_strict',
    });
    const latestListingsResponse = await fetch(`https://pro-api.coinmarketcap.com/v1/cryptocurrency/listings/latest?${latestListingsParams.toString()}`, {
        headers: {
            'X-CMC_PRO_API_KEY': apiKey,
        }
    });
    if (latestListingsResponse.status !== 200) {
        throw new Error(`failed to fetch latest coinmarketcap listings: http ${latestListingsResponse.status}`);
    }

    const latestListings = await latestListingsResponse.json() as CoinMarketCapListingsResponse;

    const metadataV2Params = new URLSearchParams({
        id: latestListings.data.map(listing => listing.id).join(","),
        aux: 'urls',
    });
    const metadataResponse = await fetch(`https://pro-api.coinmarketcap.com/v2/cryptocurrency/info?${metadataV2Params.toString()}`, {
        headers: {
            'X-CMC_PRO_API_KEY': apiKey
        }
    });
    if (metadataResponse.status !== 200) {
        throw new Error(`failed to fetch coin metadata: http ${metadataResponse.status}`);
    }

    const metadatas = await metadataResponse.json() as CoinMarketCapMetadataV2Response;

    return Object.values(metadatas.data).flatMap(data => data.urls.website.map(url => new URL(url).hostname));
}

const fetchSnapsRegistryList = async (): Promise<string[]> => {
    const snapsRegistryResponse = await fetch('https://acl.execution.metamask.io/latest/registry.json', {
        headers: {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) EthPhishingDetect/1.2.0 Safari/537.36',
        }
    });
    if (snapsRegistryResponse.status !== 200) {
        throw new Error(`failed to fetch snaps registry: http ${snapsRegistryResponse.status}`);
    }
    const snapsRegistry = await snapsRegistryResponse.json() as SnapsRegistry;

    return Object.values(snapsRegistry.verifiedSnaps)
        .flatMap(snap => [snap.metadata.author?.website, snap.metadata.website])
        .map(url => {
            if (url === undefined) return undefined;

            try {
                return new URL(url).hostname
            } catch {
                try {
                    return new URL(`https://${url}`).hostname
                } catch {
                    console.log(`failed to automatically parse url ${url}`);
                    return undefined;
                }
            }
        })
        .filter(hostname => hostname !== undefined);
}

const fetchCoinGeckoExchangesList = async (): Promise<string[]> => {
    const exchangesResponse = await fetch('https://api.coingecko.com/api/v3/exchanges?per_page=100');
    if (exchangesResponse.status !== 200) {
        throw new Error(`failed to fetch coingecko exchanges: http ${exchangesResponse.status}`);
    }
    const exchanges = await exchangesResponse.json() as CoinGeckoExchangesV3Response;

    return exchanges.map(exchange => new URL(exchange.url).hostname);
}

const fetchAndUpdateList = async (target: string, domains: string[]) => {
    const trimWWW = (domain: string) => {
        return domain.startsWith("www.") ? domain.substring(4) : domain;
    }

    await writeFile(path.join(resourcesDir, `${target}.txt`), Array.from(new Set(domains)).map(trimWWW).join("\n"));
};

const matchesList = (requested: string, want: string): boolean => {
    return requested === want || requested === 'all';
}

const main = async () => {
    const target = process.argv[2];

    if (matchesList(target, 'tranco')) {
        await fetchAndUpdateList('tranco', await fetchTrancoList());
    }

    if (matchesList(target, 'coinmarketcap')) {
        const apiKey = process.env.COINMARKETCAP_PRO_API_KEY;
        if (apiKey === undefined) {
            throw new Error('you must specify COINMARKETCAP_PRO_API_KEY');
        }
        await fetchAndUpdateList('coinmarketcap', await fetchCoinMarketCapList(apiKey));
    }

    if (matchesList(target, 'snapsregistry')) {
        await fetchAndUpdateList('snapsregistry', await fetchSnapsRegistryList());
    }

    if (matchesList(target, 'coingecko')) {
        await fetchAndUpdateList('coingecko', await fetchCoinGeckoExchangesList());
    }
};

main();