package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"encoding/xml"
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
	XMLName   xml.Name `xml:"Contact" json:"-"`
	LastName  string   `xml:"LastName,omitempty" json:"lastName,omitempty"`
	FirstName string   `xml:"FirstName,omitempty" json:"firstName,omitempty"`
	Phone     Phone    `xml:"Phone" json:"phone"`
	Groups    Groups   `xml:"Groups" json:"groups"`
}

type AddressBook struct {
	XMLName  xml.Name  `xml:"AddressBook" json:"-"`
	Contacts []Contact `xml:"Contact" json:"-"`
}

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

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World!\n")
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
	contacts, err := loadContacts("contacts.json")
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
	contacts, err := loadContacts("contacts.json")
	if err != nil {
		http.Error(w, "Failed to load contacts", http.StatusInternalServerError)
		return
	}

	templates.ExecuteTemplate(w, "list.html", contacts)
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

		existingContacts, err := loadContacts("contacts.json")
		if err != nil {
			existingContacts = []Contact{}
		}

		existingContacts = append(existingContacts, newContacts...)

		if err := saveContacts("contacts.json", existingContacts); err != nil {
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
			contacts, err := loadContacts("contacts.json")
			if err != nil {
				http.Error(w, "Failed to load contacts", http.StatusInternalServerError)
				return
			}

			idStr := r.FormValue("id")
			if idStr != "" {
				id, _ := strconv.Atoi(idStr)
				if id >= 0 && id < len(contacts) {
					contacts = append(contacts[:id], contacts[id+1:]...)
					if err := saveContacts("contacts.json", contacts); err != nil {
						http.Error(w, "Failed to save contacts", http.StatusInternalServerError)
						return
					}
				}
			}
			http.Redirect(w, r, "/contacts", http.StatusSeeOther)
			return
		}

		contacts, err := loadContacts("contacts.json")
		if err != nil {
			http.Error(w, "Failed to load contacts", http.StatusInternalServerError)
			return
		}

		idStr := r.FormValue("id")
		firstName := r.FormValue("firstName")
		lastName := r.FormValue("lastName")
		phoneNumber := r.FormValue("phoneNumber")
		phoneType := r.FormValue("phoneType")

		contact := Contact{
			FirstName: firstName,
			LastName:  lastName,
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

		if err := saveContacts("contacts.json", contacts); err != nil {
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
		contacts, err := loadContacts("contacts.json")
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

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)
	mux.HandleFunc("/phonebook.xml", addressbookHandler)
	mux.HandleFunc("/contacts", webListHandler)
	mux.HandleFunc("/contacts/edit", webEditHandler)
	mux.HandleFunc("/contacts/new", webEditHandler)
	mux.HandleFunc("/contacts/import", webImportHandler)

	loggedMux := loggingMiddleware(mux)

	port := ":8081"
	log.Printf("Starting server on http://localhost%s", port)

	if err := http.ListenAndServe(port, loggedMux); err != nil {
		log.Fatal(err)
	}
}
