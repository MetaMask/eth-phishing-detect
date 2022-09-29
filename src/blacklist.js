const fs = require("fs");
const config = require("./config");

const domains = process.argv.slice(2);
domains.forEach(domain => {
  config.blacklist.unshift(domain);
});

// Nicely pad the file
let output = JSON.stringify(config, null, 2);
output += "\n";

fs.writeFile("./src/config.json", output, (err) => {
  if (err) {
    return console.log(err);
  }
});
