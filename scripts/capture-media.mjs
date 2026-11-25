// Records the README media from the built explainer:
//   docs/media/decapsulation.png   the noise ring, histogram and breakdown
//   docs/media/ntt.gif             hovering along the butterfly network
//   docs/media/tamper.png          a flipped ciphertext bit, rejected
//   docs/media/matrix.png          A-hat and the first SampleNTT candidates
//
//   npm run build && node scripts/capture-media.mjs
//
// Uses the locally installed Chrome through Playwright and encodes the GIF
// with gifenc. Every capture uses the same fixed seeds, so the pictures
// match the numbers quoted in the README.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';
import gifenc from 'gifenc';
import { PNG } from 'pngjs';
import { preview } from 'vite';

const { GIFEncoder, quantize, applyPalette } = gifenc;
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = join(repo, 'docs', 'media');
mkdirSync(outDir, { recursive: true });

const appRoot = join(repo, 'apps', 'explainer');
const server = await preview({
  root: appRoot,
  configFile: join(appRoot, 'vite.config.ts'),
  preview: { port: 4322, strictPort: true },
  logLevel: 'warn',
});

// Fixed randomness: the README quotes numbers from exactly this exchange.
const hex = (b) => b.toString(16).padStart(2, '0').repeat(32);
const SEEDS = { d: hex(0x6c), z: hex(0x77), m: Buffer.from('ML-KEM-768 via latticework, 2026').toString('hex') };
const url = `http://localhost:4322/latticework/#set=768&d=${SEEDS.d}&z=${SEEDS.z}&m=${SEEDS.m}`;

const browser = await chromium.launch({ channel: 'chrome', headless: true });

async function open(scale) {
  const page = await browser.newPage({ viewport: { width: 1180, height: 1000 }, deviceScaleFactor: scale });
  await page.goto(url);
  await page.locator('body[data-ready=true]').waitFor();
  // The sticky settings bar would sit on top of element screenshots.
  await page.addStyleTag({ content: '.controls { position: static !important; }' });
  return page;
}

// ---------------------------------------------------------------- stills

const sharp = await open(2);
for (const [name, selector] of [
  ['decapsulation', '#decapsulation .figure'],
  ['matrix', '#matrix .figure'],
]) {
  const png = await sharp.locator(selector).first().screenshot({ scale: 'device' });
  writeFileSync(join(outDir, `${name}.png`), png);
  console.log(`${name}.png: ${(png.length / 1024).toFixed(0)} kB`);
}

await sharp.getByTestId('tamper-bit-7').click();
await sharp.getByTestId('tamper-byte').fill('1000');
await sharp.getByTestId('tamper-flip').click();
await sharp.getByTestId('tamper-verdict').getByText('Rejected').waitFor();
await sharp.getByTestId('flip-all').click();
await sharp.getByTestId('flip-all-result').getByText('rejected').waitFor({ timeout: 60_000 });
await sharp.mouse.move(0, 0);
const tamper = await sharp.locator('#tamper .figure').first().screenshot({ scale: 'device' });
const flipAll = await sharp.locator('#tamper .figure').nth(1).textContent();
console.log(`flip-all: ${flipAll}`);
writeFileSync(join(outDir, 'tamper.png'), tamper);
console.log(`tamper.png: ${(tamper.length / 1024).toFixed(0)} kB`);

// ------------------------------------------------------------------- GIF

const page = await open(1);
const canvas = page.locator('#ntt canvas');
await canvas.scrollIntoViewIfNeeded();
const box = await canvas.boundingBox();
const clip = { x: Math.floor(box.x) - 4, y: Math.floor(box.y) - 4, width: Math.ceil(box.width) + 8, height: Math.ceil(box.height) + 8 };

const frames = [];
const grab = async (hold) => frames.push({ png: await page.screenshot({ clip }), delay: hold });
const top = box.y + 24;
const rowY = (row) => top + row * 2 + 1;

await page.mouse.move(box.x + 5, box.y + 5);
await grab(900);
// Sweep a few outputs on the right, then a few inputs on the left.
for (const row of [0, 37, 74, 111, 148, 185, 222, 255]) {
  await page.mouse.move(box.x + box.width - 20, rowY(row));
  await grab(380);
}
for (const row of [255, 200, 150, 100, 50, 1]) {
  await page.mouse.move(box.x + 30, rowY(row));
  await grab(380);
}
await page.mouse.move(box.x + box.width / 2, box.y - 40);
await grab(1200);

const decoded = frames.map((f) => {
  const png = PNG.sync.read(f.png);
  return { rgba: new Uint8Array(png.data), width: png.width, height: png.height, delay: f.delay };
});
const { width, height } = decoded[0];
const sample = new Uint8Array(decoded[0].rgba.length * 3);
[0, 0.4, 0.8].forEach((p, i) => sample.set(decoded[Math.round(p * (decoded.length - 1))].rgba, i * decoded[0].rgba.length));
const palette = quantize(sample, 256);
const gif = GIFEncoder();
decoded.forEach((f, i) => {
  const index = applyPalette(f.rgba, palette);
  gif.writeFrame(index, width, height, { palette: i === 0 ? palette : undefined, delay: f.delay });
});
gif.finish();
const gifBytes = gif.bytes();
writeFileSync(join(outDir, 'ntt.gif'), gifBytes);
console.log(`ntt.gif: ${width}x${height}, ${decoded.length} frames, ${(gifBytes.length / 1024).toFixed(0)} kB`);

await browser.close();
await new Promise((r) => server.httpServer.close(r));
