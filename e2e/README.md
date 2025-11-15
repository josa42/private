# End-to-End Tests

This directory contains Playwright end-to-end tests for the grandstream-telephonebook application.

## Setup

Install dependencies:

```bash
npm install
```

## Running Tests

```bash
# Run all tests (headless)
npm test

# Run tests in headed mode (see browser)
npm run test:headed

# Run tests in UI mode (interactive)
npm run test:ui

# Show last test report
npm run test:report
```

## Test Structure

- `tests/auth.spec.js` - Authentication tests (login, logout, redirects)
- `tests/contacts.spec.js` - Contact management tests (CRUD operations, normalization)
- `tests/import.spec.js` - vCard import functionality tests
- `tests/phonebook.spec.js` - XML phonebook endpoint tests

## Test Data

Tests use an isolated data directory (`tests/data/`) that is reset between test runs to ensure test isolation.

## Configuration

See `playwright.config.js` for Playwright configuration including:
- Test directory location
- Browser configuration
- Web server setup (automatically starts the Go application)
