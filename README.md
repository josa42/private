# Grandstream Telephonebook

Ein einfacher Webserver zur Verwaltung von Kontakten für Grandstream IP-Telefone.

## Features

- 📇 Kontakte verwalten (Anlegen, Bearbeiten, Löschen)
- 📱 XML-Export für Grandstream Telefone
- 📥 vCard Import (.vcf Dateien)
- 🔧 Automatische Normalisierung von Telefonnummern
- 🔐 Login-System mit Benutzerverwaltung
- 📱 Responsive Design für Desktop und Mobile

## Installation

```bash
go build
```

## Benutzerverwaltung

### Standard-Benutzer
- **Benutzername:** admin
- **Passwort:** admin

**Wichtig:** Ändern Sie das Standard-Passwort nach der ersten Anmeldung!

### Eigenen Benutzer erstellen

Bearbeiten Sie `users.json` manuell oder verwenden Sie dieses Go-Skript:

```go
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

type User struct {
	Username string `json:"username"`
	Hash     string `json:"hash"`
	Salt     string `json:"salt"`
}

func generateSalt() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}

func hashPassword(password, salt string) string {
	hash := sha256.Sum256([]byte(password + salt))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func main() {
	username := "ihr_benutzername"
	password := "ihr_passwort"
	
	salt := generateSalt()
	hash := hashPassword(password, salt)
	
	user := User{
		Username: username,
		Hash:     hash,
		Salt:     salt,
	}
	
	// Bestehende Benutzer laden
	var users []User
	data, _ := os.ReadFile("users.json")
	json.Unmarshal(data, &users)
	
	// Benutzer hinzufügen
	users = append(users, user)
	
	// Speichern
	data, _ = json.MarshalIndent(users, "", "  ")
	os.WriteFile("users.json", data, 0600)
	
	fmt.Printf("Benutzer '%s' erstellt\n", username)
}
```

## Server starten

```bash
./grandstream-telephonebook
```

Der Server läuft dann auf http://localhost:8081

## Grandstream Konfiguration

1. Melden Sie sich im Web-Interface Ihres Grandstream Telefons an
2. Navigieren Sie zu: **Web → Settings → Phonebook → XML Phonebook**
3. Tragen Sie die URL ein: `http://ihre-server-ip:8081/phonebook.xml`
4. Stellen Sie das Download-Intervall ein (z.B. 60 Minuten)

**Hinweis:** Das Phonebook.xml ist ohne Login erreichbar, damit das Telefon darauf zugreifen kann.

## Dateien

- `contacts.json` - Kontaktdaten (wird automatisch erstellt)
- `users.json` - Benutzerdaten mit gehashten Passwörtern
- `server.log` - Server-Logs

## Sicherheit

- Passwörter werden mit SHA-256 und Salt gespeichert
- Session-basierte Authentifizierung
- HttpOnly Cookies
- Sessions laufen nach 7 Tagen ab
- `users.json` und `contacts.json` sind in `.gitignore`
