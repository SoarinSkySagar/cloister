// Renders brand/cover.html to brand/cover.png (1920x1080, 16:9) and a
// 480px-wide thumbnail preview for checking legibility at project-card size.
import { chromium } from "playwright";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { statSync } from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });
  await page.goto("file://" + join(here, "cover.html"));
  await page.evaluate(() => document.fonts.ready);
  const out = join(here, "cover.png");
  await page.screenshot({ path: out, type: "png" });

  const thumb = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 0.25 });
  await thumb.goto("file://" + join(here, "cover.html"));
  await thumb.evaluate(() => document.fonts.ready);
  await thumb.screenshot({ path: join(here, "cover-thumb.png"), type: "png" });

  const fonts = await page.evaluate(() => [...document.fonts].map((f) => `${f.family}:${f.status}`));
  console.log("fonts", fonts.join(", "));
  console.log(`cover.png ${(statSync(out).size / 1024).toFixed(0)} KB`);
} finally {
  await browser.close();
}
