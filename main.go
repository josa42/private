package main

import (
	"bufio"
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
	"os"
	"strconv"
	"strings"
	"time"
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

	templates.ExecuteTemplate(w, "list.html", contacts)
}

func normalizePhoneNumber(phone string) string {
	// Remove all spaces first
	phone = strings.ReplaceAll(phone, " ", "")
	
	// Remove invalid characters (keep only digits and +)
	var cleaned strings.Builder
	for _, char := range phone {
		if (char >= '0' && char <= '9') || char == '+' {
			cleaned.WriteRune(char)
		}
	}
	phone = cleaned.String()
	
	// German numbers: replace leading 0 with +49
	if strings.HasPrefix(phone, "0") && !strings.HasPrefix(phone, "00") {
		phone = "+49" + phone[1:]
	}
	
	// Add space after country code (+49)
	if strings.HasPrefix(phone, "+49") && len(phone) > 3 {
		// +49 1234567890 -> +49 1234567890
		areaAndNumber := phone[3:]
		
		// Find where area code ends (typically after 3-4 digits)
		// Mobile: +49 15x, +49 16x, +49 17x (3 digits area code)
		// Landline: usually 3-5 digit area codes
		if len(areaAndNumber) >= 3 {
			if strings.HasPrefix(areaAndNumber, "15") || 
			   strings.HasPrefix(areaAndNumber, "16") || 
			   strings.HasPrefix(areaAndNumber, "17") {
				// Mobile: +49 15x xxxxxxxx
				if len(areaAndNumber) >= 10 {
					phone = "+49 " + areaAndNumber[:3] + " " + areaAndNumber[3:]
				} else {
					phone = "+49 " + areaAndNumber
				}
			} else {
				// Landline: try to detect area code length
				// Common patterns: 3-5 digits
				if len(areaAndNumber) >= 10 {
					// Assume 4 digit area code for longer numbers
					phone = "+49 " + areaAndNumber[:4] + " " + areaAndNumber[4:]
				} else if len(areaAndNumber) >= 7 {
					// Assume 3 digit area code
					phone = "+49 " + areaAndNumber[:3] + " " + areaAndNumber[3:]
				} else {
					phone = "+49 " + areaAndNumber
				}
			}
		} else {
			phone = "+49 " + areaAndNumber
		}
	}
	
	return phone
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
					phone = strings.ReplaceAll(phone, " ", "")
					phone = strings.ReplaceAll(phone, "-", "")
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
		phoneNumber := r.FormValue("phoneNumber")
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
			contacts = append(contacts, contact)
		} else {
			id, _ := strconv.Atoi(idStr)
			if id >= 0 && id < len(contacts) {
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
	mux.HandleFunc("/contacts/normalize", authMiddleware(normalizeAllHandler))

	loggedMux := loggingMiddleware(mux)

	port := ":8081"
	log.Printf("Starting server on http://localhost%s", port)

	if err := http.ListenAndServe(port, loggedMux); err != nil {
		log.Fatal(err)
	}
}
