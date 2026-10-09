// Rasterise SVG files to PNG for review and for placement in the deck.
//   NODE_PATH=<node_modules> node art/render.js <in.svg> <out.png> [width_px]
// A module that exports an SVG string can be rendered with:
//   node art/render.js --module <file.js> <exportName> <out.png> [width_px]
const fs = require("fs");
const path = require("path");
const sharp = require("sharp");

(async () => {
  const a = process.argv.slice(2);
  let svg, out, width;
  if (a[0] === "--module") {
    const mod = require(path.resolve(a[1]));
    const v = mod[a[2]];
    svg = typeof v === "function" ? v() : v;
    out = a[3]; width = a[4];
  } else {
    svg = fs.readFileSync(a[0], "utf8");
    out = a[1]; width = a[2];
  }
  let img = sharp(Buffer.from(svg), { density: 144 });
  if (width) img = img.resize({ width: parseInt(width, 10) });
  await img.png().toFile(out);
  const meta = await sharp(out).metadata();
  console.log(`wrote ${out} ${meta.width}x${meta.height}`);
})().catch((e) => { console.error(e.message); process.exit(1); });
