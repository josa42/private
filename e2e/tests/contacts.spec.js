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

test.describe('Contacts Management', () => {
  test('should display contacts list page', async ({ page }) => {
    await page.goto('/contacts');
    await expect(page.locator('h1')).toContainText('Kontakte');
  });

  test('should create a new contact', async ({ page }) => {
    await page.goto('/contacts/new');
    
    await page.fill('input[name="firstName"]', 'John');
    await page.fill('input[name="lastName"]', 'Doe');
    await page.fill('input[name="phoneNumber"]', '+49 151 12345678');
    await page.selectOption('select[name="phoneType"]', 'cell');
    await page.click('button[type="submit"]');
    
    await expect(page).toHaveURL('/contacts');
    await expect(page.getByRole('cell', { name: 'John Doe' })).toBeVisible();
  });

  test('should edit an existing contact', async ({ page }) => {
    // First create a contact
    await page.goto('/contacts/new');
    await page.fill('input[name="firstName"]', 'Jane');
    await page.fill('input[name="lastName"]', 'Smith');
    await page.fill('input[name="phoneNumber"]', '+49 30 1234567');
    await page.selectOption('select[name="phoneType"]', 'work');
    await page.click('button[type="submit"]');
    
    // Now edit it
    await page.goto('/contacts');
    await page.click('a[href*="/contacts/edit?id="]');
    
    await page.fill('input[name="firstName"]', 'Janet');
    await page.click('button.btn:has-text("Speichern")');
    
    await expect(page).toHaveURL('/contacts');
    await expect(page.locator('text=Janet')).toBeVisible();
  });

  test('should delete a contact', async ({ page }) => {
    // First create a contact
    await page.goto('/contacts/new');
    await page.fill('input[name="firstName"]', 'Delete');
    await page.fill('input[name="lastName"]', 'Me');
    await page.fill('input[name="phoneNumber"]', '+49 151 99999999');
    await page.selectOption('select[name="phoneType"]', 'cell');
    await page.click('button[type="submit"]');
    
    // Now delete it
    await page.goto('/contacts');
    await expect(page.getByRole('cell', { name: 'Delete Me' })).toBeVisible();
    
    await page.click('a[href*="/contacts/edit?id="]');
    
    // Accept the confirmation dialog
    page.on('dialog', dialog => dialog.accept());
    await page.click('button.delete:has-text("Löschen")');
    
    await expect(page).toHaveURL('/contacts');
  });

  test('should normalize phone numbers', async ({ page }) => {
    // Create a contact with unnormalized phone
    await page.goto('/contacts/new');
    await page.fill('input[name="firstName"]', 'Normalize');
    await page.fill('input[name="lastName"]', 'Test');
    await page.fill('input[name="phoneNumber"]', '0151 12345678');
    await page.selectOption('select[name="phoneType"]', 'cell');
    await page.click('button[type="submit"]');
    
    // Verify unnormalized phone is visible
    await page.goto('/contacts');
    await expect(page.getByRole('cell', { name: 'Normalize Test' })).toBeVisible();
    
    // Normalize all contacts
    page.on('dialog', dialog => dialog.accept());
    await page.click('button:has-text("Normalisieren")');
    
    await expect(page).toHaveURL('/contacts');
    await expect(page.locator('text=+49 151 12345678')).toBeVisible();
  });
});
