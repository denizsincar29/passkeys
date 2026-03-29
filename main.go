package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/egregors/passkey"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/joho/godotenv"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// --- User Implementation ---

type User struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"uniqueIndex"`
	Credentials []byte `gorm:"type:blob"`
}

func (u *User) WebAuthnID() []byte {
	return []byte(fmt.Sprintf("%d", u.ID))
}

func (u *User) WebAuthnName() string {
	return u.Name
}

func (u *User) WebAuthnDisplayName() string {
	return u.Name
}

func (u *User) WebAuthnIcon() string {
	return ""
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	var creds []webauthn.Credential
	if len(u.Credentials) > 0 {
		_ = json.Unmarshal(u.Credentials, &creds)
	}
	return creds
}

func (u *User) PutCredential(c webauthn.Credential) {
	creds := u.WebAuthnCredentials()
	found := false
	for i, cred := range creds {
		if string(cred.ID) == string(c.ID) {
			creds[i] = c
			found = true
			break
		}
	}
	if !found {
		creds = append(creds, c)
	}
	u.Credentials, _ = json.Marshal(creds)
}

// --- UserStore Implementation ---

type UserStore struct {
	db *gorm.DB
}

func (s *UserStore) Create(username string) (passkey.User, error) {
	u := &User{Name: username}
	if err := s.db.Create(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}

func (s *UserStore) Update(u passkey.User) error {
	return s.db.Save(u.(*User)).Error
}

func (s *UserStore) Get(userID []byte) (passkey.User, error) {
	var u User
	if err := s.db.First(&u, "id = ?", string(userID)).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *UserStore) GetByName(username string) (passkey.User, error) {
	var u User
	if err := s.db.First(&u, "name = ?", username).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

// --- SessionStore Implementation ---

type MemorySessionStore[T webauthn.SessionData | passkey.UserSessionData] struct {
	mu   sync.RWMutex
	data map[string]T
}

func (s *MemorySessionStore[T]) Create(data T) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	s.data[token] = data
	return token, nil
}

func (s *MemorySessionStore[T]) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, token)
}

func (s *MemorySessionStore[T]) Get(token string) (*T, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.data[token]
	if !ok {
		return nil, false
	}
	return &val, true
}

func main() {
	_ = godotenv.Load()

	appDomain := os.Getenv("APP_DOMAIN")
	if appDomain == "" {
		appDomain = "localhost"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	isLocal := appDomain == "localhost"
	var origin string
	if isLocal {
		origin = "http://localhost:" + port
	} else {
		origin = "https://" + appDomain
	}

	dbDir := "db"
	_ = os.MkdirAll(dbDir, 0755)
	db, err := gorm.Open(sqlite.Open(dbDir+"/passkey.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	db.AutoMigrate(&User{})

	cfg := passkey.Config{
		WebauthnConfig: &webauthn.Config{
			RPDisplayName: "Passkey Demo",
			RPID:          appDomain,
			RPOrigins:     []string{origin},
		},
		UserStore:        &UserStore{db: db},
		AuthSessionStore: &MemorySessionStore[webauthn.SessionData]{data: make(map[string]webauthn.SessionData)},
		UserSessionStore: &MemorySessionStore[passkey.UserSessionData]{data: make(map[string]passkey.UserSessionData)},
	}

	pk, err := passkey.New(cfg, passkey.WithInsecureCookie())
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	pk.MountRoutes(mux, "/auth/")

	// =========================
	// AUTH ROUTES
	// =========================
	// The library's MountRoutes mounts:
	// /passkey/registerBegin
	// /passkey/registerFinish
	// /passkey/loginBegin
	// /passkey/loginFinish

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "templates/index.html")
	})

	log.Println("running on :" + port + " with domain " + appDomain + " and origin " + origin)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
