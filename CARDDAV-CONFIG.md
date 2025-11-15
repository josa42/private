# CardDAV Sync Configuration

## Setup

1. Kopiere `carddav-config.json.example` nach `carddav-config.json` (oder in dein `--data-dir` Verzeichnis)
2. Bearbeite die Datei mit deinen CardDAV-Zugangsdaten
3. Klicke auf "CardDAV Sync" in der Web-UI

## Konfiguration

Die `carddav-config.json` Datei enthält eine Liste von CardDAV-Quellen:

```json
{
  "sources": [
    {
      "name": "Beschreibung der Quelle",
      "url": "CardDAV Server URL",
      "username": "Benutzername",
      "password": "Passwort",
      "addressBookPath": "Optional: spezifischer Adressbuch-Pfad",
      "groupFilter": "Optional: nur diese Gruppe importieren"
    }
  ]
}
```

### Felder

- **name**: Beschreibender Name (nur für Logs)
- **url**: CardDAV Server URL
- **username**: Benutzername für Authentifizierung
- **password**: Passwort (bei iCloud: App-spezifisches Passwort!)
- **addressBookPath** (optional): Pfad zum Adressbuch (leer = Auto-Discovery)
- **groupFilter** (optional): Nur Kontakte aus dieser Gruppe (leer = alle)

## iCloud Beispiel

```json
{
  "sources": [
    {
      "name": "iCloud Familie",
      "url": "https://contacts.icloud.com/",
      "username": "max@icloud.com",
      "password": "abcd-efgh-ijkl-mnop",
      "addressBookPath": "/274887503/carddavhome/card/",
      "groupFilter": "Familie"
    }
  ]
}
```

**Wichtig für iCloud:**
- Verwende ein **App-spezifisches Passwort** von https://appleid.apple.com
- Finde deine **DSID** im Server-Log beim ersten Import
- Setze den **addressBookPath** mit deiner DSID

## Nextcloud Beispiel

```json
{
  "sources": [
    {
      "name": "Nextcloud Kontakte",
      "url": "https://nextcloud.example.com/remote.php/dav/addressbooks/users/USERNAME/contacts/",
      "username": "username",
      "password": "password"
    }
  ]
}
```

## Mehrere Quellen

Du kannst mehrere CardDAV-Quellen konfigurieren:

```json
{
  "sources": [
    {
      "name": "iCloud Familie",
      "url": "https://contacts.icloud.com/",
      "username": "user@icloud.com",
      "password": "xxxx-xxxx-xxxx-xxxx",
      "groupFilter": "Familie"
    },
    {
      "name": "iCloud Arbeit",
      "url": "https://contacts.icloud.com/",
      "username": "user@icloud.com",
      "password": "xxxx-xxxx-xxxx-xxxx",
      "groupFilter": "Arbeit"
    },
    {
      "name": "Nextcloud",
      "url": "https://nextcloud.example.com/remote.php/dav/addressbooks/users/me/contacts/",
      "username": "me",
      "password": "secret"
    }
  ]
}
```

## Nutzung

1. Klicke auf **"CardDAV Sync"** Button in der Kontaktliste
2. Die App importiert automatisch von allen konfigurierten Quellen
3. Schaue ins Log für Details über den Import

## Sicherheit

- Die Datei enthält Passwörter im Klartext!
- Setze Berechtigungen: `chmod 600 carddav-config.json`
- Speichere die Datei NICHT in einem öffentlichen Repository
- Verwende bei iCloud immer App-spezifische Passwörter

## Troubleshooting

Schaue ins Server-Log (Terminal oder `server.log`):
- Welche Quellen werden verarbeitet?
- Wie viele Kontakte wurden importiert?
- Gab es Fehler bei einer Quelle?

Beispiel-Log:
```
CardDAV Sync: Starting sync from 2 source(s)
CardDAV Sync: [1/2] Syncing from 'iCloud Familie' (https://contacts.icloud.com/)
CardDAV: Found iCloud group: 'Familie'
CardDAV: Successfully converted 25 contact(s) with phone numbers
CardDAV Sync: Imported 25 contact(s) from 'iCloud Familie'
CardDAV Sync: [2/2] Syncing from 'Nextcloud' (https://nextcloud.example.com/...)
CardDAV: Successfully converted 15 contact(s) with phone numbers
CardDAV Sync: Imported 15 contact(s) from 'Nextcloud'
CardDAV Sync: Completed! Total imported: 40 contact(s)
```
