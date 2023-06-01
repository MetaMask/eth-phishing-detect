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

updateTrancoList();
