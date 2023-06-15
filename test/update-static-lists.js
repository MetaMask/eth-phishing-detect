const sqlite3 = require("sqlite3");
const parseCsv = require("csv-parse/sync");
const fs = require("fs");
const axios = require("axios");
const join = require("path").join;
require("dotenv").config({ path: join(__dirname, ".update-lists.env") });

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

async function updateTrancoList() {
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
  const stream = fs.createWriteStream("trancoList.csv");

  try {
    const response = await axios.get(
      "https://tranco-list.eu/download/K25GW/100000",
      {
        responseType: "stream",
      }
    );

    response.data.pipe(stream);

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

  try {
    fs.unlinkSync("./tranco-temp.db");
  } catch (err) {
    console.error(err);
  }

  // Create db and fill it with entries from Tranco csv file
  const db = new sqlite3.Database("./tranco-temp.db");

  const trancoDomainsCsv = fs.readFileSync(
    __dirname + "/trancoList.csv",
    "utf8"
  );
  const trancoDomains = parseCsv.parse(trancoDomainsCsv, {
    skip_empty_lines: true,
  });

  db.on("trace", function (sqlString) {
    console.log("SQL string: " + sqlString);
  });

  db.serialize(() => {
    db.exec("CREATE TABLE tranco (ranking INTEGER, domain TEXT)");
    db.exec("CREATE INDEX domain_index ON tranco(domain);");

    // Wrapping all insert statements in a single transaction is way faster as
    // sqlite by default insert each row in a separate transaction
    db.exec("BEGIN TRANSACTION;");

    const stmt = db.prepare("INSERT INTO tranco VALUES (?,?)");
    for (let i = 0; i < trancoDomains.length; i++) {
      // check exclude list. If domain found, continue to next loop cycle
      if (excludeList.includes(trancoDomains[i][1])) continue;
      stmt.run(trancoDomains[i][0], trancoDomains[i][1]);
    }
    stmt.finalize();

    db.exec("COMMIT;");
  });

  db.close(function (err) {
    if (err) {
      process.exit(1);
    } else {
      // copy temp db file
      console.log("Copying: temp db file... ");
      fs.copyFileSync("./tranco-temp.db", "./tranco.db");
      process.exit(0);
    }
  });
}

async function updateCoinmarketcapList() {
  try {
    fs.unlinkSync("./coinmarketcap-temp.db");
  } catch (err) {
    console.error(err);
  }

  const apiKey = process.env.COINMARKETCAP_API_KEY;
  let coinsIds = [];
  let coinsMarketCaps = {};
  const coinsArray = [];
  const totalCoins = 5000; // how many coins items to retrieve in total
  const coinsPerSubCall = 250; // how many coins (IDs) will be in the query string of coins metadata subcalls

  // Create db and fill it with entries from Dappradar API responses
  const db = new sqlite3.Database("./coinmarketcap-temp.db");

  function delay(t) {
    return new Promise((resolve) => setTimeout(resolve, t));
  }

  // Call Coinmarketcap API
  try {
    // get only coins with market cap > 10M
    const response = await axios.get(
      `https://pro-api.coinmarketcap.com/v1/cryptocurrency/listings/latest?limit=${totalCoins}&start=1&sort=market_cap_strict&market_cap_min=10000000`,
      {
        headers: {
          "X-CMC_PRO_API_KEY": apiKey,
        },
      }
    );
    response.data.data.forEach((coin) => {
      coinsMarketCaps[coin.id] = coin.quote.USD.market_cap;
      coinsIds.push(coin.id);
    });

    // divide total coins (IDs) to retrieve in chunks to create multiple calls to the coin metadata endpoint
    // this because coins Ids are passed to the endpoint as a query string param and query strings have a limit on their size/length
    const subcallsCoinsIds = arrayTo2DArray1(coinsIds, coinsPerSubCall);

    try {
      for (subcallCoinsIds of subcallsCoinsIds) {
        await delay(2500);
        const response = await axios.get(
          `https://pro-api.coinmarketcap.com/v2/cryptocurrency/info?id=${subcallCoinsIds.join(
            ","
          )}`,
          {
            headers: {
              "X-CMC_PRO_API_KEY": apiKey,
            },
          }
        );

        Object.keys(response.data.data).forEach((coinId) => {
          coinsArray.push([
            response.data.data[coinId].name,
            coinsMarketCaps[coinId],
            response.data.data[coinId].urls.website[0],
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

  db.on("trace", function (sqlString) {
    console.log("SQL string: " + sqlString);
  });

  db.serialize(() => {
    db.exec(
      "CREATE TABLE coinmarketcap (name TEXT, marketcap INTEGER, domain TEXT)"
    );
    db.exec("CREATE INDEX domain_index ON coinmarketcap(domain);");

    // Wrapping all insert statements in a single transaction is way faster as
    // sqlite by default insert each row in a separate transaction
    db.exec("BEGIN TRANSACTION;");

    const stmt = db.prepare("INSERT INTO coinmarketcap VALUES (?,?,?)");

    for (coin of coinsArray) {
      try {
        let coinDomainName = "";
        if (coin[2]) {
          const coinDomainSplit1 = coin[2].split(/(https:\/\/|http:\/\/)+/);
          const coinDomainSplit2 =
            coinDomainSplit1[coinDomainSplit1.length - 1].split(/(\/)+/);
          coinDomainName = coinDomainSplit2[0].replace("www.", "");
        }

        stmt.run(coin[0], coin[1], coinDomainName);
      } catch (err) {
        console.error(err);
      }
    }

    stmt.finalize();

    db.exec("COMMIT;");
  });

  db.close(function (err) {
    if (err) {
      process.exit(1);
    } else {
      // copy temp db file
      console.log("Copying: temp db file... ");
      fs.copyFileSync("./coinmarketcap-temp.db", "./coinmarketcap.db");
      process.exit(0);
    }
  });
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
