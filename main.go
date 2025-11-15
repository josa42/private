package main

import (
	"embed"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
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
	PhoneNumber  string   `xml:"phonenumber" json:"phoneNumber"`
	AccountIndex int      `xml:"accountindex" json:"accountIndex"`
}

type Groups struct {
	XMLName xml.Name `xml:"Groups" json:"-"`
	GroupID int      `xml:"groupid" json:"groupId"`
}

type Contact struct {
	XMLName   xml.Name `xml:"Contact" json:"-"`
	LastName  string   `xml:"LastName" json:"lastName"`
	FirstName string   `xml:"FirstName" json:"firstName"`
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

func webEditHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		contacts, err := loadContacts("contacts.json")
		if err != nil {
			http.Error(w, "Failed to load contacts", http.StatusInternalServerError)
			return
		}

		idStr := r.FormValue("id")
		firstName := r.FormValue("firstName")
		lastName := r.FormValue("lastName")
		phoneNumber := r.FormValue("phoneNumber")

		contact := Contact{
			FirstName: firstName,
			LastName:  lastName,
			Phone: Phone{
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

	loggedMux := loggingMiddleware(mux)

	port := ":8081"
	log.Printf("Starting server on http://localhost%s", port)

	if err := http.ListenAndServe(port, loggedMux); err != nil {
		log.Fatal(err)
	}
}
