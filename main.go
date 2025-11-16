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
	Phone       Phone    `xml:"Phone" json:"phone"`
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
	// Only handle root path, return 404 for other paths
	if r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		templates.ExecuteTemplate(w, "404.html", nil)
		return
	}
	
	data := struct {
		Host string
	}{
		Host: r.Host,
	}
	templates.ExecuteTemplate(w, "home.html", data)
}

func loadContacts(filename string) ([]Contact, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var contacts []Contact
	if err := json.Unmarshal(data, &contacts); err != nil {
		return nil, err
	}

	// Set default type for contacts without type
	for i := range contacts {
		if contacts[i].Phone.Type == "" {
			contacts[i].Phone.Type = "cell"
		}
		// Migrate old values to lowercase
		switch contacts[i].Phone.Type {
		case "Mobile":
			contacts[i].Phone.Type = "cell"
		case "Work":
			contacts[i].Phone.Type = "work"
		case "Home":
			contacts[i].Phone.Type = "home"
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

	addressBook := AddressBook{
		Contacts: contacts,
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

	// Sort contacts by name
	sort.Slice(contacts, func(i, j int) bool {
		nameI := getContactDisplayName(contacts[i])
		nameJ := getContactDisplayName(contacts[j])
		return strings.ToLower(nameI) < strings.ToLower(nameJ)
	})

	// Check if CardDAV config exists and has sources
	config, _ := loadCardDAVConfig(dataDir + "/carddav-config.json")
	hasCardDAVConfig := config != nil && len(config.Sources) > 0

	data := struct {
		Contacts         []Contact
		HasCardDAVConfig bool
	}{
		Contacts:         contacts,
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
	return c.Phone.PhoneNumber
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

func normalizeAllHandler(w http.ResponseWriter, r *http.Request) {
	contacts, err := loadContacts(dataDir + "/contacts.json")
	if err != nil {
		http.Error(w, "Failed to load contacts", http.StatusInternalServerError)
		return
	}

	// Normalize all phone numbers
	for i := range contacts {
		contacts[i].Phone.PhoneNumber = normalizePhoneNumber(contacts[i].Phone.PhoneNumber)
	}

	if err := saveContacts(dataDir+"/contacts.json", contacts); err != nil {
		http.Error(w, "Failed to save contacts", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/contacts", http.StatusSeeOther)
}

func parseVCard(vcardData string) []Contact {
	var contacts []Contact
	scanner := bufio.NewScanner(strings.NewReader(vcardData))
	
	var currentContact *Contact
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if line == "BEGIN:VCARD" {
			currentContact = &Contact{
				Phone: Phone{
					AccountIndex: 0,
				},
				Groups: Groups{
					GroupID: 1,
				},
			}
		} else if line == "END:VCARD" {
			if currentContact != nil && currentContact.Phone.PhoneNumber != "" {
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
					if currentContact.Phone.PhoneNumber == "" {
						currentContact.Phone.PhoneNumber = phone
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
		if contact.Phone.PhoneNumber != "" {
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
		Phone: Phone{
			AccountIndex: 0,
		},
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

	// Get phone number - skip numbers with excluded labels
	// Prioritize mobile numbers over landline
	// Access TEL fields directly from card map to get parameters
	var selectedPhone string
	var phoneType string
	var mobilePhone string
	var landlinePhone string
	
	// Debug: Show filter config
	contactName := card.PreferredValue(vcard.FieldFormattedName)
	if len(phoneFilterExclude) > 0 {
		log.Printf("CardDAV DEBUG: Processing contact '%s' with filters: %v", contactName, phoneFilterExclude)
	}
	
	if telFields, ok := card[vcard.FieldTelephone]; ok {
		log.Printf("CardDAV DEBUG: Contact '%s' has %d TEL field(s)", contactName, len(telFields))
		
		for i, field := range telFields {
			if field.Value == "" {
				continue
			}
			
			// Debug: Show all params
			log.Printf("CardDAV DEBUG: TEL[%d] Value='%s', Params=%+v", i, field.Value, field.Params)
			
			// Check if this phone should be excluded by label
			shouldSkip := false
			label := ""
			
			if len(phoneFilterExclude) > 0 {
				// Check all possible label locations:
				// 1. X-ABLABEL (iOS/iCloud custom labels)
				// 2. LABEL parameter (standard vCard)
				// 3. Inside TYPE parameter values (some systems)
				// 4. Group-based labels (item1.X-ABLABEL)
				
				// Method 1: X-ABLABEL parameter
				if labelParam, ok := field.Params["X-ABLABEL"]; ok && len(labelParam) > 0 {
					label = labelParam[0]
					log.Printf("CardDAV DEBUG: Found X-ABLABEL: '%s'", label)
				}
				
				// Method 2: LABEL parameter
				if labelParam, ok := field.Params["LABEL"]; ok && len(labelParam) > 0 {
					label = labelParam[0]
					log.Printf("CardDAV DEBUG: Found LABEL: '%s'", label)
				}
				
				// Method 3: Check field.Group for item-based labels
				// iCloud stores labels as separate X-ABLABEL fields with the same Group
				if field.Group != "" && label == "" {
					log.Printf("CardDAV DEBUG: Field has Group: '%s'", field.Group)
					// Look for X-ABLABEL field with matching group
					if xAbLabelFields, ok := card["X-ABLABEL"]; ok {
						for _, labelField := range xAbLabelFields {
							if labelField.Group == field.Group {
								label = labelField.Value
								log.Printf("CardDAV DEBUG: Found group label for '%s': '%s'", field.Group, label)
								break
							}
						}
					}
					if label == "" {
						log.Printf("CardDAV DEBUG: No X-ABLABEL found for group '%s'", field.Group)
					}
				}
				
				// Check label against exclusion patterns
				for _, excludePattern := range phoneFilterExclude {
					log.Printf("CardDAV DEBUG: Checking if label '%s' contains '%s'", 
						label, excludePattern)
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
			
			// Determine if this is a mobile or landline number
			// Check TYPE parameter for CELL or VOICE
			isMobile := false
			if typeParams, ok := field.Params["TYPE"]; ok {
				for _, t := range typeParams {
					typeUpper := strings.ToUpper(t)
					if typeUpper == "CELL" || typeUpper == "MOBILE" {
						isMobile = true
						break
					}
				}
			}
			
			// Store the first mobile and first landline
			if isMobile && mobilePhone == "" {
				mobilePhone = field.Value
				log.Printf("CardDAV DEBUG: Found mobile phone '%s' (label: '%s') for contact '%s'", 
					field.Value, label, contactName)
			} else if !isMobile && landlinePhone == "" {
				landlinePhone = field.Value
				log.Printf("CardDAV DEBUG: Found landline phone '%s' (label: '%s') for contact '%s'", 
					field.Value, label, contactName)
			}
			
			// Stop after finding both mobile and landline
			if mobilePhone != "" && landlinePhone != "" {
				break
			}
		}
		
		// Prefer mobile over landline
		if mobilePhone != "" {
			selectedPhone = mobilePhone
			phoneType = "cell"
			log.Printf("CardDAV: Selected mobile phone '%s' for contact '%s'", selectedPhone, contactName)
		} else if landlinePhone != "" {
			selectedPhone = landlinePhone
			phoneType = "cell"
			log.Printf("CardDAV: Selected landline phone '%s' for contact '%s'", selectedPhone, contactName)
		}
	}

	if selectedPhone != "" {
		// Normalize phone number
		selectedPhone = normalizePhoneNumber(selectedPhone)
		contact.Phone.PhoneNumber = selectedPhone
		contact.Phone.Type = phoneType
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
		phoneNumber := normalizePhoneNumber(r.FormValue("phoneNumber"))
		phoneType := r.FormValue("phoneType")

		contact := Contact{
			FirstName:   firstName,
			LastName:    lastName,
			CompanyName: companyName,
			Phone: Phone{
				Type:         phoneType,
				PhoneNumber:  phoneNumber,
				AccountIndex: 0,
			},
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
	mux.HandleFunc("/contacts/normalize", authMiddleware(normalizeAllHandler))

	loggedMux := loggingMiddleware(mux)

	port := fmt.Sprintf(":%d", *portFlag)
	log.Printf("Starting server on http://localhost%s", port)

	if err := http.ListenAndServe(port, loggedMux); err != nil {
		log.Fatal(err)
	}
}
