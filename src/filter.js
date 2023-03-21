const config = require("./config");
const data = `arbitrum-foundation.website
arbitrum-verification.com
arbitrumclaim.com
arbltrum-foundatlons.com
airdroparbitrum.com
arbitrum-networking.com`;

const filter = (data) => {
  const lines = data.replaceAll("\n", " ").split(" ");

  const filtered = lines.filter((line) => {
    // check if line is in config blacklist
    if (config.blacklist.includes(line)) {
      return false;
    }

    return true;
  });

  const result = filtered.join(" ");
  console.log(result);
  return result;
};

filter(data);
