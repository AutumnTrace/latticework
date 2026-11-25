import { expect, test, type Page } from '@playwright/test';
import { mlKem768 } from '../packages/latticework/src/index.ts';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fill = (byte: number) => new Uint8Array(32).fill(byte);

function watchErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  page.on('pageerror', (e) => errors.push(String(e)));
  return errors;
}

test('runs an exchange where both sides end up with the same secret', async ({ page }) => {
  const errors = watchErrors(page);
  await page.goto('./');
  await expect(page.locator('body')).toHaveAttribute('data-ready', 'true');
  await expect(page.getByTestId('keys-match')).toHaveText('identical');
  const alice = await page.getByTestId('secret-alice').textContent();
  expect(alice).toMatch(/^[0-9a-f ]{67}$/);
  await expect(page.getByTestId('secret-bob')).toHaveText(alice!);
  await expect(page.getByTestId('ntt-check')).toContainText('equal');
  await expect(page.getByText('exact', { exact: true })).toBeVisible();
  await expect(page.getByTestId('candidates').locator('span').first()).toBeVisible();
  expect(errors).toEqual([]);
});

test('reproduces an exchange from the link, with the secret the library computes', async ({ page }) => {
  const d = fill(0x11);
  const z = fill(0x22);
  const m = fill(0x5a);
  const { encapsulationKey } = mlKem768.keygenInternal(d, z);
  const { sharedSecret } = mlKem768.encapsulateInternal(encapsulationKey, m);

  await page.goto(`./#set=768&d=${hex(d)}&z=${hex(z)}&m=${hex(m)}`);
  await expect(page.getByTestId('secret-bob')).toHaveText(hex(sharedSecret).replace(/(.{16})(?=.)/g, '$1 '));
});

test('switches parameter sets', async ({ page }) => {
  await page.goto('./');
  await page.getByTestId('set-1024').click();
  await expect(page.getByTestId('set-1024')).toHaveAttribute('aria-checked', 'true');
  await expect(page.locator('#exchange')).toContainText('1,568 bytes, public');
  await expect(page).toHaveURL(/set=1024/);
  await expect(page.getByTestId('keys-match')).toHaveText('identical');
});

test('new randomness gives a new secret', async ({ page }) => {
  await page.goto('./');
  const before = await page.getByTestId('secret-alice').textContent();
  await page.getByTestId('reroll').click();
  await expect(page.getByTestId('secret-alice')).not.toHaveText(before!);
  await expect(page.getByTestId('keys-match')).toHaveText('identical');
});

test('a flipped ciphertext bit is rejected, and reset restores the exchange', async ({ page }) => {
  const errors = watchErrors(page);
  await page.goto('./');
  await expect(page.getByTestId('tamper-verdict')).toContainText('Untouched');

  await page.getByTestId('tamper-bit-7').click();
  await page.getByTestId('tamper-byte').fill('1000');
  await page.getByTestId('tamper-flip').click();
  await expect(page.getByTestId('tamper-verdict')).toContainText('Rejected');
  await expect(page.getByTestId('tamper-result')).toContainText('keys differ');

  // Clicking the grid works too.
  await page.getByTestId('tamper-grid').click({ position: { x: 5, y: 5 } });
  await expect(page.getByTestId('tamper-result')).toContainText('byte 0, bit 7');

  await page.getByTestId('tamper-reset').click();
  await expect(page.getByTestId('tamper-verdict')).toContainText('Untouched');
  expect(errors).toEqual([]);
});

test('every single-bit flip of an ML-KEM-512 ciphertext is rejected', async ({ page }) => {
  await page.goto('./');
  await page.getByTestId('set-512').click();
  await page.getByTestId('flip-all').click();
  await expect(page.getByTestId('flip-all-result')).toContainText('6,144 rejected of 6,144 flips', { timeout: 30_000 });
});
