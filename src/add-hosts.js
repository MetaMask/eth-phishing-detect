const fs = require('fs');
const config = require('./config');

function addHosts(list, domains, dest) {
  domains.forEach(domain => {
    config[list].unshift(domain);
  });

  const output = JSON.stringify(config, null, 2) + '\n';

  fs.writeFile(dest, output, (err) => {
    if (err) {
      return console.log(err);
    }
  });
}

module.exports = addHosts;
