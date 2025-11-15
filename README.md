# Grandstream Telephonebook

[![CI](https://github.com/josa42/grandstream-telephonebook/actions/workflows/ci.yml/badge.svg)](https://github.com/josa42/grandstream-telephonebook/actions/workflows/ci.yml)
[![Release](https://github.com/josa42/grandstream-telephonebook/actions/workflows/release.yml/badge.svg)](https://github.com/josa42/grandstream-telephonebook/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/josa42/grandstream-telephonebook)](https://goreportcard.com/report/github.com/josa42/grandstream-telephonebook)

A simple web server for managing contacts for Grandstream IP phones.

## Features

- 📇 Manage contacts (create, edit, delete)
- 📱 XML export for Grandstream phones
- 📥 vCard import (.vcf files)
- 🔧 Phone number normalization
- 🔐 Login system with user management
- 📱 Responsive design for desktop and mobile

## Installation

```bash
go build
```

## User Management

### Creating a New User

```bash
./grandstream-telephonebook --add-user username:password
```

Examples:
```bash
# Create user "alice" with password "secret123"
./grandstream-telephonebook --add-user alice:secret123

# User with complex password (colons are supported)
./grandstream-telephonebook --add-user bob:my:complex:pass
```

The application:
- Automatically generates a random salt
- Hashes the password with SHA-256
- Saves the user to `users.json`
- Checks for duplicates

## Starting the Server

```bash
./grandstream-telephonebook
```

The server will run on http://localhost:8081

### Command Line Options

```bash
# Start server (default)
./grandstream-telephonebook

# Add user
./grandstream-telephonebook --add-user username:password

# Show help
./grandstream-telephonebook --help
```

## Grandstream Configuration

1. Log in to your Grandstream phone's web interface
2. Navigate to: **Web → Settings → Phonebook → XML Phonebook**
3. Enter the URL: `http://your-server-ip:8081/phonebook.xml`
4. Set the download interval (e.g., 60 minutes)

**Note:** The phonebook.xml is accessible without login so the phone can access it.

## Data Files

- `contacts.json` - Contact data (created automatically)
- `users.json` - User data with hashed passwords

## Security

- Passwords are stored with SHA-256 and salt
- Session-based authentication
- HttpOnly cookies
- Sessions expire after 7 days
- `users.json` and `contacts.json` are in `.gitignore`
