// @ts-check
const { test, expect } = require('@playwright/test');

test.describe('XML Phonebook', () => {
  test('should return XML phonebook', async ({ request }) => {
    const response = await request.get('/phonebook.xml');
    
    expect(response.status()).toBe(200);
    expect(response.headers()['content-type']).toContain('text/xml');
    
    const body = await response.text();
    expect(body).toContain('<?xml version="1.0"');
    expect(body).toContain('<AddressBook>');
  });

  test('should include contacts in XML', async ({ page, request }) => {
    // Login and create a contact
    await page.goto('/login');
    await page.fill('input[name="username"]', 'admin');
    await page.fill('input[name="password"]', 'admin123');
    await page.click('button[type="submit"]');
    
    await page.goto('/contacts/new');
    await page.fill('input[name="firstName"]', 'XML');
    await page.fill('input[name="lastName"]', 'Test');
    await page.fill('input[name="phoneNumber"]', '+49 151 77777777');
    await page.selectOption('select[name="phoneType"]', 'cell');
    await page.click('button[type="submit"]');
    
    // Check XML endpoint
    const response = await request.get('/phonebook.xml');
    const body = await response.text();
    
    expect(body).toContain('<FirstName>XML</FirstName>');
    expect(body).toContain('<LastName>Test</LastName>');
    expect(body).toContain('+49 151 77777777');
  });
});
