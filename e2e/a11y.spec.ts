import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on hash correctness; this
 * gates them on accessibility the same way. Scans the full page in both themes
 * with every collapsible / mutually-exclusive region revealed.
 *
 * This lab hides content in three ways:
 *   - a <details> ("Why this matters") — opened.
 *   - a tabbed Info Panel where only the active .tab-panel is display:block —
 *     all four panels are force-shown so every panel's contents are scanned.
 *   - a <dialog id="padding-modal"> shown via showModal() — scanned separately
 *     (the base page is scanned first, then the open modal on its own).
 * Animations/transitions/opacity are neutralized so nothing is scanned
 * mid-flight (e.g. the avalanche bit-cells that fade in).
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content:
      '*, *::before, *::after { animation: none !important; transition: none !important; opacity: 1 !important; }',
  });
}

async function revealCollapsibles(page: Page): Promise<void> {
  await page.evaluate(() => {
    // Open every <details>.
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    // Force every tab panel visible (only the active one is display:block).
    for (const panel of document.querySelectorAll<HTMLElement>('.tab-panel')) {
      panel.classList.add('is-active');
    }
    // Reveal any inline display:none region.
    for (const el of document.querySelectorAll<HTMLElement>('[style*="display"]')) {
      if (el.style && el.style.display === 'none') el.style.display = '';
    }
  });
}

async function scan(page: Page, context?: string): Promise<void> {
  let builder = new AxeBuilder({ page }).withTags(TAGS);
  if (context) builder = builder.include(context);
  const results = await builder.analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

async function runSuite(page: Page): Promise<void> {
  await revealCollapsibles(page);
  await neutralizeMotion(page);
  await scan(page);

  // Open the padding modal and scan it on its own.
  await page.locator('#padding-btn').click();
  await expect(page.locator('#padding-modal')).toBeVisible();
  await neutralizeMotion(page);
  await scan(page, '#padding-modal');
  await page.locator('#close-modal').click();
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await runSuite(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await runSuite(page);
});
