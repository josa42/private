package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-vcard"
	"github.com/emersion/go-webdav/carddav"
	"github.com/nyaruka/phonenumbers"
)

//go:embed templates/*
var templateFS embed.FS

var templates *template.Template

func init() {
	templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))
}

type Phone struct {
	XMLName      xml.Name `xml:"Phone" json:"-"`
	Type         string   `xml:"type,attr,omitempty" json:"type,omitempty"`
	PhoneNumber  string   `xml:"phonenumber" json:"phoneNumber"`
	AccountIndex int      `xml:"accountindex" json:"accountIndex"`
}

type Groups struct {
	XMLName xml.Name `xml:"Groups" json:"-"`
	GroupID int      `xml:"groupid" json:"groupId"`
}

type Contact struct {
	XMLName     xml.Name `xml:"Contact" json:"-"`
	LastName    string   `xml:"LastName,omitempty" json:"lastName,omitempty"`
	FirstName   string   `xml:"FirstName,omitempty" json:"firstName,omitempty"`
	CompanyName string   `xml:"Company,omitempty" json:"companyName,omitempty"`
	Phones      []Phone  `xml:"Phone" json:"phones,omitempty"`
	Groups      Groups   `xml:"Groups" json:"groups"`
	Source      string   `xml:"-" json:"source,omitempty"` // e.g. "carddav:iCloud Familie"
}

type CardDAVSource struct {
	Name              string   `json:"name"`
	URL               string   `json:"url"`
	Username          string   `json:"username"`
	Password          string   `json:"password"`
	AddressBookPath   string   `json:"addressBookPath,omitempty"`
	GroupFilter       string   `json:"groupFilter,omitempty"`
	PhoneFilterExclude []string `json:"phoneFilterExclude,omitempty"` // Exclude numbers containing these strings
}

type CardDAVConfig struct {
	Sources []CardDAVSource `json:"sources"`
}

type AddressBook struct {
	XMLName  xml.Name  `xml:"AddressBook" json:"-"`
	Contacts []Contact `xml:"Contact" json:"-"`
}

type User struct {
	Username string `json:"username"`
	Hash     string `json:"hash"`
	Salt     string `json:"salt"`
}

var sessions = make(map[string]string) // sessionID -> username
var dataDir string                      // directory for contacts and users files

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		log.Printf("[%s] %s %s %s",
			start.Format("2006-01-02 15:04:05"),
			r.Method,
			r.URL.Path,
			r.RemoteAddr,
		)

		next.ServeHTTP(w, r)
	})
}

func loadUsers() ([]User, error) {
	data, err := os.ReadFile(dataDir + "/users.json")
	if err != nil {
		return nil, err
	}
	
	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, err
	}
	
	return users, nil
}

func hashPassword(password, salt string) string {
	hash := sha256.Sum256([]byte(password + salt))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func generateSalt() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}

func authenticateUser(username, password string) bool {
	users, err := loadUsers()
	if err != nil {
		log.Printf("Error loading users: %v", err)
		return false
	}
	
	for _, user := range users {
		if user.Username == username {
			hash := hashPassword(password, user.Salt)
			return hash == user.Hash
		}
	}
	
	return false
}

func getSessionUser(r *http.Request) string {
	cookie, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	
	username, exists := sessions[cookie.Value]
	if !exists {
		return ""
	}
	
	return username
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := getSessionUser(r)
		if username == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		
		if authenticateUser(username, password) {
			sessionID := generateSalt() // reuse salt generator for session ID
			sessions[sessionID] = username
			
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    sessionID,
				Path:     "/",
				HttpOnly: true,
				MaxAge:   86400 * 7, // 7 days
			})
			
			http.Redirect(w, r, "/contacts", http.StatusSeeOther)
			return
		}
		
		data := struct {
			Error string
		}{
			Error: "Ungültiger Benutzername oder Passwort",
		}
		templates.ExecuteTemplate(w, "login.html", data)
		return
	}
	
	templates.ExecuteTemplate(w, "login.html", nil)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		delete(sessions, cookie.Value)
	}
	
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Redirect root path to /contacts, return 404 for other paths
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/contacts", http.StatusFound)
		return
	}
	
	w.WriteHeader(http.StatusNotFound)
	templates.ExecuteTemplate(w, "404.html", nil)
}

func loadContacts(filename string) ([]Contact, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Try loading as new format first
	var contacts []Contact
	if err := json.Unmarshal(data, &contacts); err != nil {
		return nil, err
	}

	// Migrate old single phone format to new multiple phones format
	for i := range contacts {
		// Check if old format (single phone field exists but phones is empty)
		var oldContact struct {
			Phone Phone `json:"phone"`
		}
		if err := json.Unmarshal(data, &[]interface{}{&oldContact}); err == nil {
			if len(contacts[i].Phones) == 0 {
				// Try to unmarshal the old "phone" field
				var rawContact map[string]interface{}
				contactData, _ := json.Marshal(map[string]interface{}{
					"lastName":    contacts[i].LastName,
					"firstName":   contacts[i].FirstName,
					"companyName": contacts[i].CompanyName,
					"groups":      contacts[i].Groups,
					"source":      contacts[i].Source,
				})
				json.Unmarshal(contactData, &rawContact)
				
				// Check if the original data has "phone" field
				var originalContacts []map[string]interface{}
				json.Unmarshal(data, &originalContacts)
				if i < len(originalContacts) {
					if phoneData, ok := originalContacts[i]["phone"].(map[string]interface{}); ok {
						phone := Phone{}
						if phoneNum, ok := phoneData["phoneNumber"].(string); ok {
							phone.PhoneNumber = phoneNum
						}
						if phoneType, ok := phoneData["type"].(string); ok {
							phone.Type = phoneType
						}
						if accountIdx, ok := phoneData["accountIndex"].(float64); ok {
							phone.AccountIndex = int(accountIdx)
						}
						
						// Migrate old type values
						if phone.Type == "" {
							phone.Type = "cell"
						}
						switch phone.Type {
						case "Mobile":
							phone.Type = "cell"
						case "Work":
							phone.Type = "work"
						case "Home":
							phone.Type = "home"
						}
						
						if phone.PhoneNumber != "" {
							contacts[i].Phones = []Phone{phone}
						}
					}
				}
			}
		}
		
		// Set default type for phones without type
		for j := range contacts[i].Phones {
			if contacts[i].Phones[j].Type == "" {
				contacts[i].Phones[j].Type = "cell"
			}
			// Migrate old values to lowercase
			switch contacts[i].Phones[j].Type {
			case "Mobile":
				contacts[i].Phones[j].Type = "cell"
			case "Work":
				contacts[i].Phones[j].Type = "work"
			case "Home":
				contacts[i].Phones[j].Type = "home"
			}
		}
	}

	return contacts, nil
}

func loadCardDAVConfig(filename string) (*CardDAVConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty config if file doesn't exist
			return &CardDAVConfig{Sources: []CardDAVSource{}}, nil
		}
		return nil, err
	}

	var config CardDAVConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func saveCardDAVConfig(filename string, config *CardDAVConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0600)
}

func saveContacts(filename string, contacts []Contact) error {
	data, err := json.MarshalIndent(contacts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func addressbookHandler(w http.ResponseWriter, r *http.Request) {
	contacts, err := loadContacts(dataDir + "/contacts.json")
	if err != nil {
		log.Printf("Error loading contacts: %v", err)
		http.Error(w, "Failed to load contacts", http.StatusInternalServerError)
		return
	}

	// Prepare contacts for XML output
	// For company contacts without names, put company name in FirstName/LastName
	xmlContacts := make([]Contact, len(contacts))
	for i, contact := range contacts {
		xmlContacts[i] = contact
		// If company name is set but no first/last name, use company name only as LastName
		// (using both FirstName and LastName causes duplicate display on phones)
		if contact.CompanyName != "" && contact.FirstName == "" && contact.LastName == "" {
			xmlContacts[i].LastName = contact.CompanyName
		}
	}

	addressBook := AddressBook{
		Contacts: xmlContacts,
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	
	xmlData, err := xml.MarshalIndent(addressBook, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, xml.Header+"%s", xmlData)
}

func webListHandler(w http.ResponseWriter, r *http.Request) {
	contacts, err := loadContacts(dataDir + "/contacts.json")
	if err != nil {
		http.Error(w, "Failed to load contacts", http.StatusInternalServerError)
		return
	}

	// Create a list with original indices
	type ContactWithID struct {
		Contact
		ID int
	}
	
	contactsWithIDs := make([]ContactWithID, len(contacts))
	for i, c := range contacts {
		contactsWithIDs[i] = ContactWithID{Contact: c, ID: i}
	}

	// Sort contacts by name
	sort.Slice(contactsWithIDs, func(i, j int) bool {
		nameI := getContactDisplayName(contactsWithIDs[i].Contact)
		nameJ := getContactDisplayName(contactsWithIDs[j].Contact)
		return strings.ToLower(nameI) < strings.ToLower(nameJ)
	})

	// Check if CardDAV config exists and has sources
	config, _ := loadCardDAVConfig(dataDir + "/carddav-config.json")
	hasCardDAVConfig := config != nil && len(config.Sources) > 0

	data := struct {
		Contacts         []ContactWithID
		HasCardDAVConfig bool
	}{
		Contacts:         contactsWithIDs,
		HasCardDAVConfig: hasCardDAVConfig,
	}

	templates.ExecuteTemplate(w, "list.html", data)
}

func getContactDisplayName(c Contact) string {
	if c.CompanyName != "" {
		return c.CompanyName
	}
	if c.FirstName != "" || c.LastName != "" {
		return c.FirstName + " " + c.LastName
	}
	if len(c.Phones) > 0 {
		return c.Phones[0].PhoneNumber
	}
	return ""
}

func normalizePhoneNumber(phone string) string {
	if phone == "" {
		return ""
	}
	
	// Parse phone number with German region as default
	num, err := phonenumbers.Parse(phone, "DE")
	if err != nil {
		// If parsing fails, return original (cleaned of spaces)
		log.Printf("Warning: Failed to parse phone number '%s': %v", phone, err)
		return strings.ReplaceAll(phone, " ", "")
	}
	
	// Format according to E.164 international format first
	e164 := phonenumbers.Format(num, phonenumbers.E164)
	
	// Now format to international format with spaces (similar to DIN 5008)
	// E.164: +4915112345678
	// We want: +49 151 12345678
	
	// Use INTERNATIONAL format which adds spaces
	formatted := phonenumbers.Format(num, phonenumbers.INTERNATIONAL)
	
	// The INTERNATIONAL format produces output like: +49 151 12345678
	// which is close to DIN 5008
	
	// For consistency, ensure German numbers follow our preferred pattern
	if strings.HasPrefix(e164, "+49") {
		// Remove all spaces first
		digitsOnly := strings.ReplaceAll(e164, " ", "")
		
		if len(digitsOnly) <= 3 {
			return digitsOnly
		}
		
		rest := digitsOnly[3:] // Everything after +49
		
		// Detect mobile numbers (15x, 16x, 17x)
		if len(rest) >= 2 && rest[0] == '1' && (rest[1] == '5' || rest[1] == '6' || rest[1] == '7') {
			// Mobile: +49 151 12345678
			if len(rest) >= 3 {
				return "+49 " + rest[:3] + " " + rest[3:]
			}
			return "+49 " + rest
		}
		
		// For landlines, use the library's INTERNATIONAL format
		// as it handles area codes correctly
		return formatted
	}
	
	// For non-German numbers, use library's INTERNATIONAL format
	return formatted
}



func parseVCard(vcardData string) []Contact {
	var contacts []Contact
	scanner := bufio.NewScanner(strings.NewReader(vcardData))
	
	var currentContact *Contact
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if line == "BEGIN:VCARD" {
			currentContact = &Contact{
				Phones: []Phone{},
				Groups: Groups{
					GroupID: 1,
				},
			}
		} else if line == "END:VCARD" {
			if currentContact != nil && len(currentContact.Phones) > 0 {
				contacts = append(contacts, *currentContact)
			}
			currentContact = nil
		} else if currentContact != nil {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := parts[0]
				value := parts[1]
				
				if strings.HasPrefix(key, "FN") {
					nameParts := strings.Fields(value)
					if len(nameParts) >= 2 {
						currentContact.FirstName = nameParts[0]
						currentContact.LastName = strings.Join(nameParts[1:], " ")
					} else if len(nameParts) == 1 {
						currentContact.FirstName = nameParts[0]
					}
				} else if strings.HasPrefix(key, "N") {
					nameParts := strings.Split(value, ";")
					if len(nameParts) >= 2 {
						currentContact.LastName = nameParts[0]
						currentContact.FirstName = nameParts[1]
					}
				} else if strings.HasPrefix(key, "TEL") {
					phone := strings.TrimSpace(value)
					phone = normalizePhoneNumber(phone)
					// Add the first phone we find
					if len(currentContact.Phones) == 0 {
						currentContact.Phones = append(currentContact.Phones, Phone{
							PhoneNumber:  phone,
							Type:         "cell",
							AccountIndex: 0,
						})
					}
				}
			}
		}
	}
	
	return contacts
}

func webImportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		file, _, err := r.FormFile("vcardfile")
		if err != nil {
			http.Error(w, "Failed to read file", http.StatusBadRequest)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		var vcardData strings.Builder
		for scanner.Scan() {
			vcardData.WriteString(scanner.Text())
			vcardData.WriteString("\n")
		}

		newContacts := parseVCard(vcardData.String())
		
		if len(newContacts) == 0 {
			http.Error(w, "No valid contacts found in vCard file", http.StatusBadRequest)
			return
		}

		existingContacts, err := loadContacts(dataDir + "/contacts.json")
		if err != nil {
			existingContacts = []Contact{}
		}

		existingContacts = append(existingContacts, newContacts...)

		if err := saveContacts(dataDir+"/contacts.json", existingContacts); err != nil {
			http.Error(w, "Failed to save contacts", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/contacts", http.StatusSeeOther)
		return
	}

	templates.ExecuteTemplate(w, "import.html", nil)
}

func importFromCardDAV(cardDAVURL, username, password, addressBookPath, groupFilter string, phoneFilterExclude []string) ([]Contact, error) {
	ctx := context.Background()
	
	// Parse and validate URL
	parsedURL, err := url.Parse(cardDAVURL)
	if err != nil {
		return nil, fmt.Errorf("invalid CardDAV URL: %v", err)
	}

	// Create HTTP client with basic auth
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Set credentials
	if username != "" && password != "" {
		// iCloud app-specific passwords can be with or without dashes
		// Try original password first, then without dashes
		passwords := []string{password}
		if strings.Contains(password, "-") {
			passwordNoDashes := strings.ReplaceAll(password, "-", "")
			passwords = append(passwords, passwordNoDashes)
		}

		var lastErr error
		for i, pwd := range passwords {
			parsedURL.User = url.UserPassword(username, pwd)
			client, err := carddav.NewClient(httpClient, parsedURL.String())
			if err != nil {
				lastErr = fmt.Errorf("failed to create CardDAV client: %v", err)
				continue
			}

			// Try to find principal to test authentication
			_, err = client.FindCurrentUserPrincipal(ctx)
			if err == nil {
				// Success! Continue with this password
				log.Printf("CardDAV: Authentication successful (password variant %d)", i+1)
				return importFromCardDAVWithClient(ctx, client, addressBookPath, groupFilter, phoneFilterExclude)
			}
			lastErr = err
			log.Printf("CardDAV: Authentication failed with password variant %d: %v", i+1, err)
		}

		return nil, fmt.Errorf("authentication failed: %v (Hinweis: Bei iCloud brauchst du ein App-spezifisches Passwort von https://appleid.apple.com. Probiere das Passwort mit UND ohne Bindestriche)", lastErr)
	}

	// No credentials - try anonymous
	client, err := carddav.NewClient(httpClient, cardDAVURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create CardDAV client: %v", err)
	}

	return importFromCardDAVWithClient(ctx, client, addressBookPath, groupFilter, phoneFilterExclude)
}

func importFromCardDAVWithClient(ctx context.Context, client *carddav.Client, addressBookPath, groupFilter string, phoneFilterExclude []string) ([]Contact, error) {
	// Find address books
	var addressBookURL string
	if addressBookPath != "" {
		addressBookURL = addressBookPath
	} else {
		// Auto-discover principal and address books
		principal, err := client.FindCurrentUserPrincipal(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to find user principal: %v", err)
		}

		log.Printf("CardDAV: Found principal: %s", principal)

		addressBooks, err := client.FindAddressBooks(ctx, principal)
		if err != nil {
			// iCloud workaround: construct address book path from principal
			// Principal format: /DSID/principal/ -> Address book: /DSID/carddavhome/card/
			if strings.Contains(principal, "/principal/") {
				dsid := strings.Trim(principal, "/")
				dsid = strings.Split(dsid, "/")[0]
				addressBookURL = "/" + dsid + "/carddavhome/card/"
				log.Printf("CardDAV: Auto-discovery failed, trying iCloud workaround with URL: %s", addressBookURL)
				log.Printf("CardDAV: (Hinweis: Du kannst diese URL direkt als 'Adressbuch Pfad' eingeben)")
			} else {
				return nil, fmt.Errorf("failed to find address books: %v (Principal: %s)", err, principal)
			}
		} else {
			if len(addressBooks) == 0 {
				return nil, fmt.Errorf("no address books found (Principal: %s)", principal)
			}

			// Log all found address books
			log.Printf("CardDAV: Found %d address book(s):", len(addressBooks))
			for i, ab := range addressBooks {
				log.Printf("  [%d] %s - %s", i, ab.Name, ab.Path)
			}

			// Use first address book
			addressBookURL = addressBooks[0].Path
			log.Printf("CardDAV: Using address book: %s", addressBookURL)
		}
	}

	// Query all contacts from address book
	query := carddav.AddressBookQuery{
		DataRequest: carddav.AddressDataRequest{
			AllProp: true,
		},
	}

	log.Printf("CardDAV: Querying contacts from: %s", addressBookURL)
	addressObjects, err := client.QueryAddressBook(ctx, addressBookURL, &query)
	if err != nil {
		return nil, fmt.Errorf("failed to query address book: %v (URL: %s)", err, addressBookURL)
	}

	log.Printf("CardDAV: Retrieved %d address object(s)", len(addressObjects))

	// If group filter is specified, try to find group members (iCloud support)
	var groupMemberUIDs map[string]bool
	groupFilterLower := strings.ToLower(strings.TrimSpace(groupFilter))
	
	if groupFilterLower != "" {
		log.Printf("CardDAV: Filtering contacts by group: '%s'", groupFilter)
		
		// First pass: Find group objects and extract member UIDs (for iCloud)
		groupMemberUIDs = make(map[string]bool)
		for _, obj := range addressObjects {
			if obj.Card == nil {
				continue
			}
			
			// Check if this is a group object (iCloud uses X-ADDRESSBOOKSERVER-KIND)
			kind := obj.Card.Value("X-ADDRESSBOOKSERVER-KIND")
			if kind == "group" {
				// This is a group, check if it matches our filter
				groupName := obj.Card.PreferredValue(vcard.FieldFormattedName)
				if groupName != "" && strings.Contains(strings.ToLower(groupName), groupFilterLower) {
					log.Printf("CardDAV: Found iCloud group: '%s'", groupName)
					
					// Extract member UIDs
					members := obj.Card.Values("X-ADDRESSBOOKSERVER-MEMBER")
					for _, member := range members {
						// Member format: urn:uuid:XXXX or /path/XXXX.vcf
						memberUID := extractUIDFromMember(member)
						if memberUID != "" {
							groupMemberUIDs[memberUID] = true
						}
					}
					log.Printf("CardDAV: Group '%s' has %d member(s)", groupName, len(groupMemberUIDs))
				}
			}
		}
	}

	// Convert vCards to contacts with optional group filtering
	var contacts []Contact
	var filteredCount int
	var noPhoneCount int
	var processedCount int
	
	for _, obj := range addressObjects {
		if obj.Card == nil {
			continue
		}
		
		// Skip group objects themselves
		kind := obj.Card.Value("X-ADDRESSBOOKSERVER-KIND")
		if kind == "group" {
			continue
		}

		// Check group filter if specified
		if groupFilterLower != "" {
			matchesGroup := false
			
			// Method 1: Check iCloud group membership by UID
			if len(groupMemberUIDs) > 0 {
				contactUID := obj.Card.Value(vcard.FieldUID)
				if contactUID != "" && groupMemberUIDs[contactUID] {
					matchesGroup = true
					if processedCount < 3 {
						log.Printf("CardDAV: Contact UID '%s' matches iCloud group", contactUID)
					}
				}
			}
			
			// Method 2: Check standard CATEGORIES field (for Nextcloud, etc.)
			if !matchesGroup {
				categories := obj.Card.Values(vcard.FieldCategories)
				
				// Debug: Log categories for first few contacts
				if processedCount < 3 && len(categories) > 0 {
					log.Printf("CardDAV: Contact has categories: %v", categories)
				}
				
				for _, category := range categories {
					categoryLower := strings.ToLower(strings.TrimSpace(category))
					if categoryLower == groupFilterLower || strings.Contains(categoryLower, groupFilterLower) {
						matchesGroup = true
						break
					}
				}
			}
			
			if !matchesGroup {
				filteredCount++
				continue
			}
		}

		processedCount++
		
		contact := vCardToContactWithFilter(obj.Card, phoneFilterExclude)
		if len(contact.Phones) > 0 {
			contacts = append(contacts, contact)
		} else {
			noPhoneCount++
			// Debug: Log contact name without phone
			if noPhoneCount <= 5 {
				name := contact.FirstName + " " + contact.LastName
				if name == " " {
					name = contact.CompanyName
				}
				log.Printf("CardDAV: Contact '%s' has no phone number, skipping", name)
			}
		}
	}

	if len(phoneFilterExclude) > 0 {
		log.Printf("CardDAV: Phone filter patterns: %v", phoneFilterExclude)
	}
	if groupFilterLower != "" {
		log.Printf("CardDAV: Group filter results: %d matched group, %d filtered out", processedCount, filteredCount)
	}
	if noPhoneCount > 0 {
		log.Printf("CardDAV: Skipped %d contact(s) without phone numbers", noPhoneCount)
	}
	log.Printf("CardDAV: Successfully converted %d contact(s) with phone numbers", len(contacts))
	return contacts, nil
}

func extractUIDFromMember(member string) string {
	// Member can be in format:
	// urn:uuid:12345678-1234-1234-1234-123456789012
	// /274887503/carddavhome/card/12345678-1234-1234-1234-123456789012.vcf
	
	// Extract UUID from urn:uuid: format
	if strings.HasPrefix(member, "urn:uuid:") {
		return strings.TrimPrefix(member, "urn:uuid:")
	}
	
	// Extract UUID from path format
	if strings.Contains(member, "/") {
		parts := strings.Split(member, "/")
		if len(parts) > 0 {
			lastPart := parts[len(parts)-1]
			// Remove .vcf extension if present
			return strings.TrimSuffix(lastPart, ".vcf")
		}
	}
	
	return member
}

func vCardToContact(card vcard.Card) Contact {
	return vCardToContactWithFilter(card, nil)
}

func vCardToContactWithFilter(card vcard.Card, phoneFilterExclude []string) Contact {
	contact := Contact{
		Phones: []Phone{},
		Groups: Groups{
			GroupID: 1,
		},
	}

	// Get formatted name
	fn := card.PreferredValue(vcard.FieldFormattedName)
	if fn != "" {
		nameParts := strings.Fields(fn)
		if len(nameParts) >= 2 {
			contact.FirstName = nameParts[0]
			contact.LastName = strings.Join(nameParts[1:], " ")
		} else if len(nameParts) == 1 {
			contact.FirstName = nameParts[0]
		}
	}

	// Try structured name if formatted name didn't work
	if contact.FirstName == "" && contact.LastName == "" {
		names := card.Names()
		if len(names) > 0 {
			n := names[0]
			contact.LastName = n.FamilyName
			contact.FirstName = n.GivenName
		}
	}

	// Get organization
	orgs := card.Values(vcard.FieldOrganization)
	if len(orgs) > 0 {
		contact.CompanyName = orgs[0]
	}

	// Get phone numbers - collect mobile, home, and work
	// Skip numbers with excluded labels
	var mobilePhone, homePhone, workPhone string
	
	contactName := card.PreferredValue(vcard.FieldFormattedName)
	
	if telFields, ok := card[vcard.FieldTelephone]; ok {
		for _, field := range telFields {
			if field.Value == "" {
				continue
			}
			
			// Check if this phone should be excluded by label
			shouldSkip := false
			label := ""
			
			if len(phoneFilterExclude) > 0 {
				// Check all possible label locations:
				// 1. X-ABLABEL (iOS/iCloud custom labels)
				// 2. LABEL parameter (standard vCard)
				// 3. Group-based labels (item1.X-ABLABEL)
				
				// Method 1: X-ABLABEL parameter
				if labelParam, ok := field.Params["X-ABLABEL"]; ok && len(labelParam) > 0 {
					label = labelParam[0]
				}
				
				// Method 2: LABEL parameter
				if labelParam, ok := field.Params["LABEL"]; ok && len(labelParam) > 0 {
					label = labelParam[0]
				}
				
				// Method 3: Check field.Group for item-based labels
				// iCloud stores labels as separate X-ABLABEL fields with the same Group
				if field.Group != "" && label == "" {
					// Look for X-ABLABEL field with matching group
					if xAbLabelFields, ok := card["X-ABLABEL"]; ok {
						for _, labelField := range xAbLabelFields {
							if labelField.Group == field.Group {
								label = labelField.Value
								break
							}
						}
					}
				}
				
				// Check label against exclusion patterns
				for _, excludePattern := range phoneFilterExclude {
					if strings.Contains(label, excludePattern) {
						shouldSkip = true
						log.Printf("CardDAV: Skipping phone '%s' (label: '%s') for contact '%s' - label contains '%s'", 
							field.Value, label, contactName, excludePattern)
						break
					}
				}
			}
			
			if shouldSkip {
				continue
			}
			
			// Determine phone type from TYPE parameter
			phoneType := ""
			if typeParams, ok := field.Params["TYPE"]; ok {
				for _, t := range typeParams {
					typeUpper := strings.ToUpper(t)
					if typeUpper == "CELL" || typeUpper == "MOBILE" {
						phoneType = "cell"
						break
					} else if typeUpper == "HOME" {
						phoneType = "home"
						break
					} else if typeUpper == "WORK" {
						phoneType = "work"
						break
					}
				}
			}
			
			// Store by type (one of each)
			if phoneType == "cell" && mobilePhone == "" {
				mobilePhone = field.Value
			} else if phoneType == "home" && homePhone == "" {
				homePhone = field.Value
			} else if phoneType == "work" && workPhone == "" {
				workPhone = field.Value
			} else if phoneType == "" && mobilePhone == "" {
				// Default unknown types to mobile
				mobilePhone = field.Value
			}
		}
	}

	// Build phones array
	if mobilePhone != "" {
		contact.Phones = append(contact.Phones, Phone{
			PhoneNumber:  normalizePhoneNumber(mobilePhone),
			Type:         "cell",
			AccountIndex: 0,
		})
		log.Printf("CardDAV: Added mobile phone for contact '%s'", contactName)
	}
	if homePhone != "" {
		contact.Phones = append(contact.Phones, Phone{
			PhoneNumber:  normalizePhoneNumber(homePhone),
			Type:         "home",
			AccountIndex: 0,
		})
		log.Printf("CardDAV: Added home phone for contact '%s'", contactName)
	}
	if workPhone != "" {
		contact.Phones = append(contact.Phones, Phone{
			PhoneNumber:  normalizePhoneNumber(workPhone),
			Type:         "work",
			AccountIndex: 0,
		})
		log.Printf("CardDAV: Added work phone for contact '%s'", contactName)
	}

	return contact
}


func webCardDAVSyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Load CardDAV config
	config, err := loadCardDAVConfig(dataDir + "/carddav-config.json")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to load config: %v", err), http.StatusInternalServerError)
		return
	}

	if len(config.Sources) == 0 {
		http.Error(w, "No CardDAV sources configured in carddav-config.json", http.StatusBadRequest)
		return
	}

	log.Printf("CardDAV Sync: Starting sync from %d source(s)", len(config.Sources))

	// Load existing contacts (keep only non-synced contacts)
	existingContacts, err := loadContacts(dataDir + "/contacts.json")
	if err != nil {
		existingContacts = []Contact{}
	}

	// Remove old synced contacts (they will be re-synced)
	var manualContacts []Contact
	for _, c := range existingContacts {
		if c.Source == "" {
			manualContacts = append(manualContacts, c)
		}
	}
	log.Printf("CardDAV Sync: Keeping %d manually created contact(s)", len(manualContacts))

	totalImported := 0

	// Import from each source
	for i, source := range config.Sources {
		log.Printf("CardDAV Sync: [%d/%d] Syncing from '%s' (%s)", i+1, len(config.Sources), source.Name, source.URL)

		newContacts, err := importFromCardDAV(source.URL, source.Username, source.Password, source.AddressBookPath, source.GroupFilter, source.PhoneFilterExclude)
		if err != nil {
			log.Printf("CardDAV Sync: Error importing from '%s': %v", source.Name, err)
			continue
		}

		// Mark contacts with source
		sourceName := fmt.Sprintf("carddav:%s", source.Name)
		for i := range newContacts {
			newContacts[i].Source = sourceName
		}

		log.Printf("CardDAV Sync: Imported %d contact(s) from '%s'", len(newContacts), source.Name)
		manualContacts = append(manualContacts, newContacts...)
		totalImported += len(newContacts)
	}

	// Save all contacts (manual + newly synced)
	if err := saveContacts(dataDir+"/contacts.json", manualContacts); err != nil {
		http.Error(w, "Failed to save contacts", http.StatusInternalServerError)
		return
	}

	log.Printf("CardDAV Sync: Completed! Total imported: %d contact(s)", totalImported)
	http.Redirect(w, r, "/contacts", http.StatusSeeOther)
}

func webEditHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		action := r.FormValue("action")
		
		if action == "delete" {
			contacts, err := loadContacts(dataDir + "/contacts.json")
			if err != nil {
				http.Error(w, "Failed to load contacts", http.StatusInternalServerError)
				return
			}

			idStr := r.FormValue("id")
			if idStr != "" {
				id, _ := strconv.Atoi(idStr)
				if id >= 0 && id < len(contacts) {
					// Prevent deleting synced contacts
					if contacts[id].Source != "" {
						http.Error(w, "Cannot delete synced contact. This contact is managed by CardDAV sync.", http.StatusForbidden)
						return
					}
					contacts = append(contacts[:id], contacts[id+1:]...)
					if err := saveContacts(dataDir+"/contacts.json", contacts); err != nil {
						http.Error(w, "Failed to save contacts", http.StatusInternalServerError)
						return
					}
				}
			}
			http.Redirect(w, r, "/contacts", http.StatusSeeOther)
			return
		}

		contacts, err := loadContacts(dataDir + "/contacts.json")
		if err != nil {
			http.Error(w, "Failed to load contacts", http.StatusInternalServerError)
			return
		}

		idStr := r.FormValue("id")
		firstName := r.FormValue("firstName")
		lastName := r.FormValue("lastName")
		companyName := r.FormValue("companyName")
		phoneMobile := normalizePhoneNumber(r.FormValue("phoneMobile"))
		phoneHome := normalizePhoneNumber(r.FormValue("phoneHome"))
		phoneWork := normalizePhoneNumber(r.FormValue("phoneWork"))

		// Build phones array
		var phones []Phone
		if phoneMobile != "" {
			phones = append(phones, Phone{
				Type:         "cell",
				PhoneNumber:  phoneMobile,
				AccountIndex: 0,
			})
		}
		if phoneHome != "" {
			phones = append(phones, Phone{
				Type:         "home",
				PhoneNumber:  phoneHome,
				AccountIndex: 0,
			})
		}
		if phoneWork != "" {
			phones = append(phones, Phone{
				Type:         "work",
				PhoneNumber:  phoneWork,
				AccountIndex: 0,
			})
		}

		// Require at least one phone number
		if len(phones) == 0 {
			http.Error(w, "At least one phone number is required", http.StatusBadRequest)
			return
		}

		contact := Contact{
			FirstName:   firstName,
			LastName:    lastName,
			CompanyName: companyName,
			Phones:      phones,
			Groups: Groups{
				GroupID: 1,
			},
		}

		if idStr == "" {
			// New contact - always allowed
			contacts = append(contacts, contact)
		} else {
			// Edit existing contact
			id, _ := strconv.Atoi(idStr)
			if id >= 0 && id < len(contacts) {
				// Prevent editing synced contacts
				if contacts[id].Source != "" {
					http.Error(w, "Cannot edit synced contact. This contact is managed by CardDAV sync.", http.StatusForbidden)
					return
				}
				contacts[id] = contact
			}
		}

		if err := saveContacts(dataDir+"/contacts.json", contacts); err != nil {
			http.Error(w, "Failed to save contacts", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/contacts", http.StatusSeeOther)
		return
	}

	idStr := r.URL.Query().Get("id")
	var contact Contact
	isNew := idStr == ""

	if !isNew {
		contacts, err := loadContacts(dataDir + "/contacts.json")
		if err != nil {
			http.Error(w, "Failed to load contacts", http.StatusInternalServerError)
			return
		}
		id, _ := strconv.Atoi(idStr)
		if id >= 0 && id < len(contacts) {
			contact = contacts[id]
			// Prevent editing synced contacts
			if contact.Source != "" {
				http.Error(w, "Cannot edit synced contact. This contact is managed by CardDAV sync.", http.StatusForbidden)
				return
			}
		}
	}

	data := struct {
		Contact Contact
		ID      string
		IsNew   bool
	}{
		Contact: contact,
		ID:      idStr,
		IsNew:   isNew,
	}
	templates.ExecuteTemplate(w, "edit.html", data)
}

func addUser(credentials string) error {
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid format, expected username:password")
	}

	username := parts[0]
	password := parts[1]

	if username == "" || password == "" {
		return fmt.Errorf("username and password cannot be empty")
	}

	users, err := loadUsers()
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load users: %v", err)
	}

	// Check if user already exists
	for _, user := range users {
		if user.Username == username {
			return fmt.Errorf("user '%s' already exists", username)
		}
	}

	salt := generateSalt()
	hash := hashPassword(password, salt)

	newUser := User{
		Username: username,
		Hash:     hash,
		Salt:     salt,
	}

	users = append(users, newUser)

	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal users: %v", err)
	}

	if err := os.WriteFile(dataDir+"/users.json", data, 0600); err != nil {
		return fmt.Errorf("failed to write users.json: %v", err)
	}

	return nil
}

func main() {
	addUserFlag := flag.String("add-user", "", "Add a new user (format: username:password)")
	dataDirFlag := flag.String("data-dir", ".", "Directory for contacts and users files (default: current directory)")
	portFlag := flag.Int("port", 8080, "Port to listen on (default: 8080)")
	flag.Parse()

	dataDir = *dataDirFlag

	if *addUserFlag != "" {
		if err := addUser(*addUserFlag); err != nil {
			log.Fatalf("Error adding user: %v", err)
		}
		log.Printf("User added successfully")
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", authMiddleware(handler))
	mux.HandleFunc("/phonebook.xml", addressbookHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/contacts", authMiddleware(webListHandler))
	mux.HandleFunc("/contacts/edit", authMiddleware(webEditHandler))
	mux.HandleFunc("/contacts/new", authMiddleware(webEditHandler))
	mux.HandleFunc("/contacts/import", authMiddleware(webImportHandler))
	mux.HandleFunc("/contacts/sync-carddav", authMiddleware(webCardDAVSyncHandler))

	loggedMux := loggingMiddleware(mux)

	port := fmt.Sprintf(":%d", *portFlag)
	log.Printf("Starting server on http://localhost%s", port)

	if err := http.ListenAndServe(port, loggedMux); err != nil {
		log.Fatal(err)
	}
}
