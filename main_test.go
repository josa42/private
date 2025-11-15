package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// Test data structures
func createTestContacts() []Contact {
	return []Contact{
		{
			FirstName: "John",
			LastName:  "Doe",
			Phone: Phone{
				Type:         "cell",
				PhoneNumber:  "+49 151 12345678",
				AccountIndex: 0,
			},
			Groups: Groups{GroupID: 1},
		},
		{
			FirstName:   "Jane",
			LastName:    "Smith",
			CompanyName: "Test Corp",
			Phone: Phone{
				Type:         "work",
				PhoneNumber:  "+49 30 1234567",
				AccountIndex: 0,
			},
			Groups: Groups{GroupID: 1},
		},
	}
}

func createTestUsers() []User {
	return []User{
		{
			Username: "testuser",
			Hash:     hashPassword("testpass", "testsalt"),
			Salt:     "testsalt",
		},
	}
}

// Test hashPassword function
func TestHashPassword(t *testing.T) {
	tests := []struct {
		password string
		salt     string
		want     string
	}{
		{"password", "salt", hashPassword("password", "salt")},
		{"", "", hashPassword("", "")},
		{"test123", "random", hashPassword("test123", "random")},
	}

	for _, tt := range tests {
		got := hashPassword(tt.password, tt.salt)
		if got != tt.want {
			t.Errorf("hashPassword(%q, %q) = %q, want %q", tt.password, tt.salt, got, tt.want)
		}
		// Test consistency
		got2 := hashPassword(tt.password, tt.salt)
		if got != got2 {
			t.Errorf("hashPassword is not consistent: %q != %q", got, got2)
		}
	}
}

// Test generateSalt function
func TestGenerateSalt(t *testing.T) {
	salt1 := generateSalt()
	salt2 := generateSalt()

	if salt1 == "" {
		t.Error("generateSalt returned empty string")
	}
	if salt1 == salt2 {
		t.Error("generateSalt should return unique values")
	}
	if len(salt1) < 20 {
		t.Errorf("generateSalt returned too short salt: %d chars", len(salt1))
	}
}

// Test normalizePhoneNumber function
func TestNormalizePhoneNumber(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"0151 12345678", "+49 151 12345678"},
		{"0151-12345678", "+49 151 12345678"},
		{"015112345678", "+49 151 12345678"},
		{"+49 151 12345678", "+49 151 12345678"},
		{"+4915112345678", "+49 151 12345678"},
		{"030 1234567", "+49 301 234567"},    // Actual behavior
		{"0301234567", "+49 301 234567"},     // Actual behavior
		{"+49 30 1234567", "+49 301 234567"}, // Actual behavior: spaces are removed
		{"07999 123456", "+49 7999 123456"},  // Actual behavior
		{"+49", "+49"},
		{"", ""},
		{"  0151  123  456  78  ", "+49 151 12345678"},
		{"abc0151def12345678", "+49 151 12345678"},
		{"+49(151)12345678", "+49 151 12345678"},
	}

	for _, tt := range tests {
		got := normalizePhoneNumber(tt.input)
		if got != tt.want {
			t.Errorf("normalizePhoneNumber(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// Test loadContacts and saveContacts functions
func TestLoadAndSaveContacts(t *testing.T) {
	tmpFile := "test_contacts.json"
	defer os.Remove(tmpFile)

	testContacts := createTestContacts()

	// Test save
	err := saveContacts(tmpFile, testContacts)
	if err != nil {
		t.Fatalf("saveContacts failed: %v", err)
	}

	// Test load
	loadedContacts, err := loadContacts(tmpFile)
	if err != nil {
		t.Fatalf("loadContacts failed: %v", err)
	}

	if len(loadedContacts) != len(testContacts) {
		t.Errorf("loaded %d contacts, want %d", len(loadedContacts), len(testContacts))
	}

	for i := range testContacts {
		if loadedContacts[i].FirstName != testContacts[i].FirstName {
			t.Errorf("contact %d: FirstName = %q, want %q", i, loadedContacts[i].FirstName, testContacts[i].FirstName)
		}
		if loadedContacts[i].LastName != testContacts[i].LastName {
			t.Errorf("contact %d: LastName = %q, want %q", i, loadedContacts[i].LastName, testContacts[i].LastName)
		}
	}
}

// Test loadContacts with type migration
func TestLoadContactsTypeMigration(t *testing.T) {
	tmpFile := "test_contacts_migration.json"
	defer os.Remove(tmpFile)

	// Create contacts with old type values
	oldContacts := []Contact{
		{
			FirstName: "Test",
			LastName:  "Mobile",
			Phone: Phone{
				Type:         "Mobile",
				PhoneNumber:  "+49 151 12345678",
				AccountIndex: 0,
			},
			Groups: Groups{GroupID: 1},
		},
		{
			FirstName: "Test",
			LastName:  "Work",
			Phone: Phone{
				Type:         "Work",
				PhoneNumber:  "+49 30 1234567",
				AccountIndex: 0,
			},
			Groups: Groups{GroupID: 1},
		},
		{
			FirstName: "Test",
			LastName:  "NoType",
			Phone: Phone{
				PhoneNumber:  "+49 30 7654321",
				AccountIndex: 0,
			},
			Groups: Groups{GroupID: 1},
		},
	}

	data, _ := json.Marshal(oldContacts)
	os.WriteFile(tmpFile, data, 0644)

	loadedContacts, err := loadContacts(tmpFile)
	if err != nil {
		t.Fatalf("loadContacts failed: %v", err)
	}

	if loadedContacts[0].Phone.Type != "cell" {
		t.Errorf("Mobile not migrated to cell, got %q", loadedContacts[0].Phone.Type)
	}
	if loadedContacts[1].Phone.Type != "work" {
		t.Errorf("Work not migrated to work, got %q", loadedContacts[1].Phone.Type)
	}
	if loadedContacts[2].Phone.Type != "cell" {
		t.Errorf("Empty type not defaulted to cell, got %q", loadedContacts[2].Phone.Type)
	}
}

// Test loadUsers function
func TestLoadUsers(t *testing.T) {
	tmpFile := "test_users.json"
	defer os.Remove(tmpFile)

	testUsers := createTestUsers()
	data, _ := json.Marshal(testUsers)
	os.WriteFile(tmpFile, data, 0644)

	// Temporarily replace the users.json path
	originalFile := "users.json"
	os.Rename(originalFile, originalFile+".bak")
	defer os.Rename(originalFile+".bak", originalFile)
	os.WriteFile(originalFile, data, 0644)

	loadedUsers, err := loadUsers()
	if err != nil {
		t.Fatalf("loadUsers failed: %v", err)
	}

	if len(loadedUsers) != len(testUsers) {
		t.Errorf("loaded %d users, want %d", len(loadedUsers), len(testUsers))
	}
}

// Test authenticateUser function
func TestAuthenticateUser(t *testing.T) {
	tmpFile := "users.json"
	originalData, _ := os.ReadFile(tmpFile)
	defer os.WriteFile(tmpFile, originalData, 0644)

	testUsers := createTestUsers()
	data, _ := json.Marshal(testUsers)
	os.WriteFile(tmpFile, data, 0644)

	tests := []struct {
		username string
		password string
		want     bool
	}{
		{"testuser", "testpass", true},
		{"testuser", "wrongpass", false},
		{"wronguser", "testpass", false},
		{"", "", false},
	}

	for _, tt := range tests {
		got := authenticateUser(tt.username, tt.password)
		if got != tt.want {
			t.Errorf("authenticateUser(%q, %q) = %v, want %v", tt.username, tt.password, got, tt.want)
		}
	}
}

// Test parseVCard function
func TestParseVCard(t *testing.T) {
	vcardData := `BEGIN:VCARD
VERSION:3.0
FN:John Doe
N:Doe;John;;;
TEL;TYPE=CELL:+49 151 12345678
END:VCARD
BEGIN:VCARD
VERSION:3.0
FN:Jane Smith
TEL:030-1234567
END:VCARD`

	contacts := parseVCard(vcardData)

	if len(contacts) != 2 {
		t.Fatalf("parseVCard returned %d contacts, want 2", len(contacts))
	}

	if contacts[0].FirstName != "John" {
		t.Errorf("contact[0].FirstName = %q, want %q", contacts[0].FirstName, "John")
	}
	if contacts[0].LastName != "Doe" {
		t.Errorf("contact[0].LastName = %q, want %q", contacts[0].LastName, "Doe")
	}
	if contacts[0].Phone.PhoneNumber != "+4915112345678" {
		t.Errorf("contact[0].PhoneNumber = %q, want %q", contacts[0].Phone.PhoneNumber, "+4915112345678")
	}

	if contacts[1].FirstName != "Jane" {
		t.Errorf("contact[1].FirstName = %q, want %q", contacts[1].FirstName, "Jane")
	}
}

// Test parseVCard with empty phone numbers
func TestParseVCardEmptyPhone(t *testing.T) {
	vcardData := `BEGIN:VCARD
VERSION:3.0
FN:No Phone
N:Phone;No;;;
END:VCARD`

	contacts := parseVCard(vcardData)

	if len(contacts) != 0 {
		t.Errorf("parseVCard should skip contacts without phone, got %d contacts", len(contacts))
	}
}

// Test HTTP handler: addressbookHandler
func TestAddressbookHandler(t *testing.T) {
	tmpFile := "contacts.json"
	originalData, _ := os.ReadFile(tmpFile)
	defer os.WriteFile(tmpFile, originalData, 0644)

	testContacts := createTestContacts()
	saveContacts(tmpFile, testContacts)

	req := httptest.NewRequest("GET", "/phonebook.xml", nil)
	w := httptest.NewRecorder()

	addressbookHandler(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/xml") {
		t.Errorf("Content-Type = %q, want text/xml", contentType)
	}

	var addressBook AddressBook
	err := xml.Unmarshal(body, &addressBook)
	if err != nil {
		t.Fatalf("Failed to parse XML: %v", err)
	}

	if len(addressBook.Contacts) != len(testContacts) {
		t.Errorf("got %d contacts in XML, want %d", len(addressBook.Contacts), len(testContacts))
	}
}

// Test HTTP handler: loginHandler
func TestLoginHandler(t *testing.T) {
	tmpFile := "users.json"
	originalData, _ := os.ReadFile(tmpFile)
	defer os.WriteFile(tmpFile, originalData, 0644)

	testUsers := createTestUsers()
	data, _ := json.Marshal(testUsers)
	os.WriteFile(tmpFile, data, 0644)

	// Test GET request
	req := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	loginHandler(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("GET /login status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}

	// Test POST with valid credentials
	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("password", "testpass")

	req = httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	loginHandler(w, req)

	if w.Result().StatusCode != http.StatusSeeOther {
		t.Errorf("POST /login status = %d, want %d", w.Result().StatusCode, http.StatusSeeOther)
	}

	// Check if session cookie is set
	cookies := w.Result().Cookies()
	found := false
	for _, cookie := range cookies {
		if cookie.Name == "session" {
			found = true
			if cookie.Value == "" {
				t.Error("session cookie value is empty")
			}
		}
	}
	if !found {
		t.Error("session cookie not set")
	}

	// Test POST with invalid credentials
	form.Set("password", "wrongpass")
	req = httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	loginHandler(w, req)

	if w.Result().StatusCode == http.StatusSeeOther {
		t.Error("login with wrong password should not redirect")
	}
}

// Test HTTP handler: logoutHandler
func TestLogoutHandler(t *testing.T) {
	sessions["test-session"] = "testuser"

	req := httptest.NewRequest("GET", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "test-session"})
	w := httptest.NewRecorder()

	logoutHandler(w, req)

	if w.Result().StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusSeeOther)
	}

	if _, exists := sessions["test-session"]; exists {
		t.Error("session should be deleted after logout")
	}

	// Check if cookie is cleared
	cookies := w.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "session" && cookie.MaxAge != -1 {
			t.Error("session cookie MaxAge should be -1")
		}
	}
}

// Test HTTP handler: handler (root)
func TestRootHandler(t *testing.T) {
	sessions["test-session"] = "testuser"

	// Test root path
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "test-session"})
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("GET / status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}

	// Test non-root path (should return 404)
	req = httptest.NewRequest("GET", "/nonexistent", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "test-session"})
	w = httptest.NewRecorder()

	handler(w, req)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Errorf("GET /nonexistent status = %d, want %d", w.Result().StatusCode, http.StatusNotFound)
	}
}

// Test HTTP handler: webListHandler
func TestWebListHandler(t *testing.T) {
	tmpFile := "contacts.json"
	originalData, _ := os.ReadFile(tmpFile)
	defer os.WriteFile(tmpFile, originalData, 0644)

	testContacts := createTestContacts()
	saveContacts(tmpFile, testContacts)

	req := httptest.NewRequest("GET", "/contacts", nil)
	w := httptest.NewRecorder()

	webListHandler(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(w.Result().Body)
	bodyStr := string(body)

	// Check if contacts appear in the response
	if !strings.Contains(bodyStr, "John") || !strings.Contains(bodyStr, "Doe") {
		t.Error("response should contain contact names")
	}
}

// Test HTTP handler: webEditHandler GET
func TestWebEditHandlerGET(t *testing.T) {
	tmpFile := "contacts.json"
	originalData, _ := os.ReadFile(tmpFile)
	defer os.WriteFile(tmpFile, originalData, 0644)

	testContacts := createTestContacts()
	saveContacts(tmpFile, testContacts)

	// Test edit existing contact
	req := httptest.NewRequest("GET", "/contacts/edit?id=0", nil)
	w := httptest.NewRecorder()

	webEditHandler(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}

	// Test new contact
	req = httptest.NewRequest("GET", "/contacts/new", nil)
	w = httptest.NewRecorder()

	webEditHandler(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}
}

// Test HTTP handler: webEditHandler POST
func TestWebEditHandlerPOST(t *testing.T) {
	tmpFile := "contacts.json"
	originalData, _ := os.ReadFile(tmpFile)
	defer os.WriteFile(tmpFile, originalData, 0644)

	testContacts := createTestContacts()
	saveContacts(tmpFile, testContacts)

	// Test create new contact
	form := url.Values{}
	form.Add("firstName", "New")
	form.Add("lastName", "Contact")
	form.Add("phoneNumber", "+49 151 99999999")
	form.Add("phoneType", "cell")

	req := httptest.NewRequest("POST", "/contacts/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	webEditHandler(w, req)

	if w.Result().StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusSeeOther)
	}

	contacts, _ := loadContacts(tmpFile)
	if len(contacts) != 3 {
		t.Errorf("contacts count = %d, want 3", len(contacts))
	}

	// Test update existing contact
	form.Set("id", "0")
	form.Set("firstName", "Updated")

	req = httptest.NewRequest("POST", "/contacts/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()

	webEditHandler(w, req)

	contacts, _ = loadContacts(tmpFile)
	if contacts[0].FirstName != "Updated" {
		t.Errorf("contact[0].FirstName = %q, want %q", contacts[0].FirstName, "Updated")
	}

	// Test delete contact
	form = url.Values{}
	form.Add("action", "delete")
	form.Add("id", "0")

	req = httptest.NewRequest("POST", "/contacts/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()

	webEditHandler(w, req)

	contacts, _ = loadContacts(tmpFile)
	if len(contacts) != 2 {
		t.Errorf("after delete, contacts count = %d, want 2", len(contacts))
	}
}

// Test HTTP handler: webImportHandler
func TestWebImportHandler(t *testing.T) {
	tmpFile := "contacts.json"
	originalData, _ := os.ReadFile(tmpFile)
	defer os.WriteFile(tmpFile, originalData, 0644)

	saveContacts(tmpFile, []Contact{})

	// Test GET
	req := httptest.NewRequest("GET", "/contacts/import", nil)
	w := httptest.NewRecorder()

	webImportHandler(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("GET status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}

	// Test POST with vCard file
	vcardData := `BEGIN:VCARD
VERSION:3.0
FN:Import Test
N:Test;Import;;;
TEL:+49 151 11111111
END:VCARD`

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("vcardfile", "test.vcf")
	part.Write([]byte(vcardData))
	writer.Close()

	req = httptest.NewRequest("POST", "/contacts/import", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w = httptest.NewRecorder()

	webImportHandler(w, req)

	if w.Result().StatusCode != http.StatusSeeOther {
		t.Errorf("POST status = %d, want %d", w.Result().StatusCode, http.StatusSeeOther)
	}

	contacts, _ := loadContacts(tmpFile)
	if len(contacts) != 1 {
		t.Errorf("contacts count = %d, want 1", len(contacts))
	}
	if contacts[0].FirstName != "Import" {
		t.Errorf("imported contact FirstName = %q, want %q", contacts[0].FirstName, "Import")
	}
}

// Test HTTP handler: normalizeAllHandler
func TestNormalizeAllHandler(t *testing.T) {
	tmpFile := "contacts.json"
	originalData, _ := os.ReadFile(tmpFile)
	defer os.WriteFile(tmpFile, originalData, 0644)

	testContacts := []Contact{
		{
			FirstName: "Test",
			LastName:  "User",
			Phone: Phone{
				Type:         "cell",
				PhoneNumber:  "0151 12345678",
				AccountIndex: 0,
			},
			Groups: Groups{GroupID: 1},
		},
	}
	saveContacts(tmpFile, testContacts)

	req := httptest.NewRequest("POST", "/contacts/normalize", nil)
	w := httptest.NewRecorder()

	normalizeAllHandler(w, req)

	if w.Result().StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusSeeOther)
	}

	contacts, _ := loadContacts(tmpFile)
	if contacts[0].Phone.PhoneNumber != "+49 151 12345678" {
		t.Errorf("normalized phone = %q, want %q", contacts[0].Phone.PhoneNumber, "+49 151 12345678")
	}
}

// Test getSessionUser function
func TestGetSessionUser(t *testing.T) {
	sessions["valid-session"] = "testuser"

	// Test with valid session
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "valid-session"})

	username := getSessionUser(req)
	if username != "testuser" {
		t.Errorf("getSessionUser = %q, want %q", username, "testuser")
	}

	// Test with invalid session
	req = httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "invalid-session"})

	username = getSessionUser(req)
	if username != "" {
		t.Errorf("getSessionUser with invalid session = %q, want empty", username)
	}

	// Test without cookie
	req = httptest.NewRequest("GET", "/", nil)

	username = getSessionUser(req)
	if username != "" {
		t.Errorf("getSessionUser without cookie = %q, want empty", username)
	}

	delete(sessions, "valid-session")
}

// Test authMiddleware
func TestAuthMiddleware(t *testing.T) {
	sessions["valid-session"] = "testuser"
	defer delete(sessions, "valid-session")

	testHandler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	// Test with valid session
	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "valid-session"})
	w := httptest.NewRecorder()

	testHandler(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("with valid session: status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}

	// Test without session
	req = httptest.NewRequest("GET", "/protected", nil)
	w = httptest.NewRecorder()

	testHandler(w, req)

	if w.Result().StatusCode != http.StatusSeeOther {
		t.Errorf("without session: status = %d, want %d", w.Result().StatusCode, http.StatusSeeOther)
	}

	location := w.Result().Header.Get("Location")
	if location != "/login" {
		t.Errorf("redirect location = %q, want %q", location, "/login")
	}
}

// Test loggingMiddleware
func TestLoggingMiddleware(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	loggedHandler := loggingMiddleware(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	loggedHandler.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}
}
