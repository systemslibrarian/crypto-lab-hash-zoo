import { test } from '@playwright/test';
import { boot, driveAllStates, NARROW } from './gate';

/**
 * WCAG A/AA regression gate. Deploys are already gated on hash correctness;
 * this gates them on accessibility the same way.
 *
 * Every state this lab can render is scanned in both themes at desktop and
 * phone width. See `gate.ts` for why nothing is injected into the page, why
 * each scan asserts its content first, and why `violations` is not the whole
 * oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(180_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
  });

  // A full axe pass at 380px is slow: narrow width reflows the digest table and
  // bit grids into scrolling boxes, giving axe far more nodes to walk.
  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(180_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
  });
}
