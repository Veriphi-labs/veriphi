const fs = require('node:fs');
const path = require('node:path');

const bin = fs.readdirSync(__dirname).find(
  f => f.startsWith('veriphi_core_node.') && f.endsWith('.node')
);

if (!bin) {
  throw new Error('Native addon not found. Did you run `npm run build`?');
}

module.exports = require(path.join(__dirname, bin));