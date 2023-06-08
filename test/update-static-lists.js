const sqlite3 = require("sqlite3");
const parseCsv = require("csv-parse/sync");
const fs = require("fs");
const axios = require("axios");

async function updateTrancoList() {
  // Download updated list
  const stream = fs.createWriteStream("trancoTop1m.csv");

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
    __dirname + "/trancoTop1m.csv",
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

async function updateDappradarList() {
  try {
    fs.unlinkSync("./dappradar-temp.db");
  } catch (err) {
    console.error(err);
  }

  const projectId = "";
  const apiKey = "";

  // Create db and fill it with entries from Dappradar API responses
  const db = new sqlite3.Database("./dappradar-temp.db");
  let dappDomains = [];

  function delay(t) {
    return new Promise((resolve) => setTimeout(resolve, t));
  }

  // Call Dappradar API
  try {
    const response = await axios.get(
      `https://api.dappradar.com/${projectId}/dapps?resultsPerPage=50`,
      {
        headers: {
          "X-BLOBR-KEY": apiKey,
        },
      }
    );

    for (const dappItem of response.data.results) {
      try {
        await delay(500);
        const dapp = await axios.get(
          `https://api.dappradar.com/${projectId}/dapps/${dappItem.dappId}`,
          {
            headers: {
              "X-BLOBR-KEY": apiKey,
            },
          }
        );
        dappDomains.push([dapp.name, dapp.website]);
      } catch (error) {
        console.error(
          `Problems while calling Dappradar API dapp endpoint for dapp: ${dappItem.dappId}. Error: ${error}`
        );
      }
    }
  } catch (error) {
    console.error(
      "Problems while calling Dappradar API dapps listing endpoint. Error: " +
        error
    );
    process.exit(1);
  }

  db.on("trace", function (sqlString) {
    console.log("SQL string: " + sqlString);
  });

  db.serialize(() => {
    db.exec("CREATE TABLE dappradar (name TEXT, website TEXT)");
    db.exec("CREATE INDEX website_index ON dappradar(website);");

    // Wrapping all insert statements in a single transaction is way faster as
    // sqlite by default insert each row in a separate transaction
    db.exec("BEGIN TRANSACTION;");

    const stmt = db.prepare("INSERT INTO dappradar VALUES (?,?)");

    for (dapp of dappDomains) {
      const dappDomainSplit1 = dapp[1].split(/(https:\/\/|http:\/\/)+/);
      const dappDomainSplit2 = dappDomainSplit1[2].split(/(\/)+/);
      const dappDomainName = dappDomainSplit2[0].replace("www.", "");
      stmt.run(dapp[0], dappDomainName);
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
      fs.copyFileSync("./dappradar-temp.db", "./dappradar.db");
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

  const apiKey = "";
  let coinsIds = [];
  const coinsArray = [];

  // Create db and fill it with entries from Dappradar API responses
  const db = new sqlite3.Database("./coinmarketcap-temp.db");

  function delay(t) {
    return new Promise((resolve) => setTimeout(resolve, t));
  }

  // Call Coinmarketcap API
  try {
    const response = await axios.get(
      "https://pro-api.coinmarketcap.com/v1/cryptocurrency/listings/latest?limit=100",
      {
        headers: {
          "X-CMC_PRO_API_KEY": apiKey,
        },
      }
    );
    response.data.data.forEach((coin) => {
      coinsIds.push(coin.id);
    });

    try {
      await delay(2500);
      const response = await axios.get(
        `https://pro-api.coinmarketcap.com/v2/cryptocurrency/info?id=${coinsIds.join(
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
          response.data.data[coinId].urls.website[0],
        ]);
      });
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
    db.exec("CREATE TABLE coinmarketcap (name TEXT, domain TEXT)");
    db.exec("CREATE INDEX domain_index ON coinmarketcap(domain);");

    // Wrapping all insert statements in a single transaction is way faster as
    // sqlite by default insert each row in a separate transaction
    db.exec("BEGIN TRANSACTION;");

    const stmt = db.prepare("INSERT INTO coinmarketcap VALUES (?,?)");

    for (coin of coinsArray) {
      const coinDomainSplit1 = coin[1].split(/(https:\/\/|http:\/\/)+/);
      const coinDomainSplit2 = coinDomainSplit1[2].split(/(\/)+/);
      const coinDomainName = coinDomainSplit2[0].replace("www.", "");
      stmt.run(coin[0], coinDomainName);
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
  case "dappradar":
    updateDappradarList();
    break;
  default:
    console.log(
      'You need to specify either: "tranco" | "coinmarketcap" | "dappradar"'
    );
    break;
}
