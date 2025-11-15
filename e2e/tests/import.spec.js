// @ts-check
const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

// Login before each test and reset contacts
test.beforeEach(async ({ page }) => {
  // Reset contacts to empty array
  const contactsPath = path.join(__dirname, 'data', 'contacts.json');
  fs.writeFileSync(contactsPath, '[]');
  
  await page.goto('/login');
  await page.fill('input[name="username"]', 'admin');
  await page.fill('input[name="password"]', 'admin123');
  await page.click('button[type="submit"]');
  await expect(page).toHaveURL('/contacts');
});

test.describe('vCard Import', () => {
  test('should display import page', async ({ page }) => {
    await page.goto('/contacts/import');
    await expect(page.locator('h1')).toContainText('vCard importieren');
  });

  test('should import vCard file', async ({ page }) => {
    await page.goto('/contacts/import');
    
    // Create a vCard file content
    const vcardContent = `BEGIN:VCARD
VERSION:3.0
FN:Import Test
N:Test;Import;;;
TEL:+49 151 11111111
END:VCARD`;
    
    // Set file to upload
    const buffer = Buffer.from(vcardContent);
    await page.setInputFiles('input[type="file"]', {
      name: 'test.vcf',
      mimeType: 'text/vcard',
      buffer: buffer,
    });
    
    await page.click('button[type="submit"]');
    
    await expect(page).toHaveURL('/contacts');
    // Check for the name parts separately to avoid matching the import button text
    await expect(page.getByRole('cell', { name: 'Import Test' })).toBeVisible();
  });
});
