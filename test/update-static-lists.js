const fs = require("fs");
const needle = require("needle");
const join = require("path").join;
require("dotenv").config({ path: join(__dirname, "/.update-lists.env") });

const DB_PATH = join(__dirname) + "/db";

const ENDPOINTS = {
  TRANCO_LIST: "https://tranco-list.eu/download/K25GW/100000",
  COINMARKETCAP:
    "https://pro-api.coinmarketcap.com/v1/cryptocurrency/listings/latest?limit=5000&start=1&sort=market_cap_strict&market_cap_min=10000000",
  COINMARKETCAP_COIN_INFO:
    "https://pro-api.coinmarketcap.com/v2/cryptocurrency/info?id=",
};

function arrayTo2DArray1(arr, size) {
  const res = [];
  for (let i = 0; i < arr.length; i++) {
    if (i % size === 0) {
      // Push a new array containing the current value to the res array
      res.push([arr[i]]);
    } else {
      // Push the current value to the current array
      res[res.length - 1].push(arr[i]);
    }
  }
  return res;
}

const touchFile = (path) => {
  const time = new Date();
  try {
    fs.utimesSync(path, time, time);
  } catch (err) {
    fs.closeSync(fs.openSync(path, "w"));
  }
};

async function updateTrancoList() {
  const PATH_CSV = DB_PATH + "/trancoList.csv";

  // This is a list of "bad domains" (false positive) that we don't want to include in the final generated DB
  const excludeList = [
    "simdif.com",
    "gb.net",
    "btcs.love",
    "ferozo.com",
    "im-creator.com",
    "free-ethereum.io",
    "890m.com",
    "b5z.net",
    "test.com",
  ];
  // Download updated list
  const stream = fs.createWriteStream(PATH_CSV);

  try {
    needle.get(ENDPOINTS.TRANCO_LIST).pipe(stream);

    await new Promise((resolve, reject) => {
      stream.on("finish", resolve);
      stream.on("error", reject);
    });
  } catch (error) {
    console.error(
      "Problems while downloading the latest list. Error: " + error
    );
    process.exit(1);
  }

  if (fs.existsSync(DB_PATH + "/trancos-temp")) {
    try {
      fs.unlinkSync(DB_PATH + "/trancos-temp");
    } catch (err) {
      console.error(err);
    }
  }

  await touchFile(PATH_CSV);

  const trancoDomainsCsv = fs.readFileSync(PATH_CSV, "utf8");
  // Replace everything before a comma with empty string and convert line feeds to ln
  let trancoDomains = trancoDomainsCsv.replace(/.*,/g, "");
  trancoDomains = trancoDomains.replace(/\r\n/g, "\n");

  // Exclude false positive (bad domains) from tranco list
  const re = new RegExp(`^(${excludeList.join("|")})$\n`, "gm");

  trancoDomains = trancoDomains.replace(re, "");

  try {
    fs.writeFileSync(DB_PATH + "/trancos-temp", trancoDomains);

    // copy temp list file
    console.log("Copying: temp list file... ");
    fs.copyFileSync(DB_PATH + "/trancos-temp", DB_PATH + "/trancos");
    process.exit(0);
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

async function updateCoinmarketcapList() {
  try {
    fs.unlinkSync(DB_PATH + "/coinmarketcaps-temp");
  } catch (err) {
    console.error(err);
  }

  const apiKey = process.env.COINMARKETCAP_API_KEY;
  let coinsIds = [];
  let coinsMarketCaps = {};
  const coinsArray = [];
  const coinsPerSubCall = 250; // how many coins (IDs) will be in the query string of coins metadata subcalls

  function delay(t) {
    return new Promise((resolve) => setTimeout(resolve, t));
  }

  // Call Coinmarketcap API
  try {
    // get only coins with market cap > 10M
    const response = await needle("get", ENDPOINTS.COINMARKETCAP, {
      headers: {
        "X-CMC_PRO_API_KEY": apiKey,
      },
    });
    response.body.data.forEach((coin) => {
      coinsMarketCaps[coin.id] = coin.quote.USD.market_cap;
      coinsIds.push(coin.id);
    });

    // divide total coins (IDs) to retrieve in chunks to create multiple calls to the coin metadata endpoint
    // this because coins Ids are passed to the endpoint as a query string param and query strings have a limit on their size/length
    const subcallsCoinsIds = arrayTo2DArray1(coinsIds, coinsPerSubCall);

    try {
      for (subcallCoinsIds of subcallsCoinsIds) {
        await delay(2500);
        const response = await needle(
          "get",
          `${ENDPOINTS.COINMARKETCAP_COIN_INFO}${subcallCoinsIds.join(",")}`,
          {
            headers: {
              "X-CMC_PRO_API_KEY": apiKey,
            },
          }
        );

        Object.keys(response.body.data).forEach((coinId) => {
          coinsArray.push([
            response.body.data[coinId].name,
            coinsMarketCaps[coinId],
            response.body.data[coinId].urls.website[0],
          ]);
        });
      }
    } catch (error) {
      console.error(
        `Problems while calling Coinmarketcap API coins details endpoint. Error: ${error}`
      );
      process.exit(1);
    }
  } catch (error) {
    console.error(
      "Problems while calling Coinmarketcap API coins listing endpoint. Error: " +
        error
    );
    process.exit(1);
  }

  for (coin of coinsArray) {
    try {
      let coinDomainName = "";
      if (coin[2]) {
        const coinDomainSplit1 = coin[2].split(/(https:\/\/|http:\/\/)+/);
        const coinDomainSplit2 =
          coinDomainSplit1[coinDomainSplit1.length - 1].split(/(\/)+/);
        coinDomainName = coinDomainSplit2[0].replace("www.", "");
      }

      fs.appendFileSync(
        DB_PATH + "/coinmarketcaps-temp",
        coinDomainName + "\n"
      );
    } catch (err) {
      console.error(err);
    }
  }

  try {
    // copy temp list file
    console.log("Copying: temp list file... ");
    fs.copyFileSync(
      DB_PATH + "/coinmarketcaps-temp",
      DB_PATH + "/coinmarketcaps"
    );
    process.exit(0);
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

const target = process.argv[2];

switch (target) {
  case "tranco":
    updateTrancoList();
    break;
  case "coinmarketcap":
    updateCoinmarketcapList();
    break;
  default:
    console.log('You need to specify either: "tranco" OR "coinmarketcap"');
    break;
}
