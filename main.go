package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/egregors/passkey"
	"github.com/glebarez/sqlite"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
)

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
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		log.Printf("Warning: failed to create db directory: %v", err)
	}
	db, err := gorm.Open(sqlite.Open(dbDir+"/passkey.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&User{}); err != nil {
		log.Fatal(err)
	}

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

	wa, err := webauthn.New(cfg.WebauthnConfig)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	const (
		authSessionCookieName = "asid"
		userSessionCookieName = "usid"
	)

	// --- Passkey Handlers ---

	mux.HandleFunc("/auth/passkey/registerBegin", func(w http.ResponseWriter, r *http.Request) {
		var u struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		user, err := cfg.UserStore.GetByName(u.Username)
		if err != nil {
			user, err = cfg.UserStore.Create(u.Username)
			if err != nil {
				http.Error(w, "failed to create user: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		options, session, err := wa.BeginRegistration(user)
		if err != nil {
			http.Error(w, "failed to begin registration: "+err.Error(), http.StatusInternalServerError)
			return
		}
		t, err := cfg.AuthSessionStore.Create(*session)
		if err != nil {
			http.Error(w, "failed to create auth session", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     authSessionCookieName,
			Value:    t,
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
		})

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(options)
	})

	mux.HandleFunc("/auth/passkey/registerFinish", func(w http.ResponseWriter, r *http.Request) {
		sid, err := r.Cookie(authSessionCookieName)
		if err != nil {
			http.Error(w, "auth session cookie missing", http.StatusBadRequest)
			return
		}

		session, ok := cfg.AuthSessionStore.Get(sid.Value)
		if !ok {
			http.Error(w, "auth session not found", http.StatusBadRequest)
			return
		}

		user, err := cfg.UserStore.Get(session.UserID)
		if err != nil {
			http.Error(w, "user not found", http.StatusInternalServerError)
			return
		}

		credential, err := wa.FinishRegistration(user, *session, r)
		if err != nil {
			http.Error(w, "failed to finish registration: "+err.Error(), http.StatusInternalServerError)
			return
		}

		user.PutCredential(*credential)
		if err := cfg.UserStore.Update(user); err != nil {
			log.Printf("failed to update user credentials: %v", err)
		}
		cfg.AuthSessionStore.Delete(sid.Value)

		// Auto-login after registration
		t, err := cfg.UserSessionStore.Create(passkey.UserSessionData{
			UserID:  user.WebAuthnID(),
			Expires: time.Now().Add(time.Hour),
		})
		if err == nil {
			http.SetCookie(w, &http.Cookie{
				Name:     userSessionCookieName,
				Value:    t,
				Path:     "/",
				MaxAge:   3600,
				HttpOnly: true,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode("Registration Success")
	})

	mux.HandleFunc("/auth/passkey/loginBegin", func(w http.ResponseWriter, r *http.Request) {
		var u struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			// It's okay if body is empty for discovery login, but we should handle parse errors
			if err != io.EOF {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
		}

		var options *protocol.CredentialAssertion
		var session *webauthn.SessionData
		var err error

		if u.Username != "" {
			user, err := cfg.UserStore.GetByName(u.Username)
			if err != nil {
				http.Error(w, "user not found", http.StatusNotFound)
				return
			}
			options, session, err = wa.BeginLogin(user)
		} else {
			options, session, err = wa.BeginDiscoverableLogin()
		}

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		t, err := cfg.AuthSessionStore.Create(*session)
		if err != nil {
			http.Error(w, "failed to create auth session", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     authSessionCookieName,
			Value:    t,
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
		})

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(options)
	})

	mux.HandleFunc("/auth/passkey/loginFinish", func(w http.ResponseWriter, r *http.Request) {
		sid, err := r.Cookie(authSessionCookieName)
		if err != nil {
			http.Error(w, "auth session cookie missing", http.StatusBadRequest)
			return
		}

		session, ok := cfg.AuthSessionStore.Get(sid.Value)
		if !ok {
			http.Error(w, "auth session not found", http.StatusBadRequest)
			return
		}

		var user passkey.User
		var credential *webauthn.Credential

		if len(session.UserID) > 0 {
			user, err = cfg.UserStore.Get(session.UserID)
			if err != nil {
				http.Error(w, "user not found", http.StatusInternalServerError)
				return
			}
			credential, err = wa.FinishLogin(user, *session, r)
		} else {
			userHandler := func(rawID, userHandle []byte) (webauthn.User, error) {
				return cfg.UserStore.Get(userHandle)
			}
			waUser, cred, err2 := wa.FinishPasskeyLogin(userHandler, *session, r)
			if err2 != nil {
				http.Error(w, err2.Error(), http.StatusInternalServerError)
				return
			}
			user = waUser.(passkey.User)
			credential = cred
			err = nil
		}

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		user.PutCredential(*credential)
		if err := cfg.UserStore.Update(user); err != nil {
			log.Printf("failed to update user credentials: %v", err)
		}
		cfg.AuthSessionStore.Delete(sid.Value)

		t, err := cfg.UserSessionStore.Create(passkey.UserSessionData{
			UserID:  user.WebAuthnID(),
			Expires: time.Now().Add(time.Hour),
		})
		if err == nil {
			http.SetCookie(w, &http.Cookie{
				Name:     userSessionCookieName,
				Value:    t,
				Path:     "/",
				MaxAge:   3600,
				HttpOnly: true,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode("Login Success")
	})

	// --- Notes Handlers ---

	mux.HandleFunc("/notes/get", func(w http.ResponseWriter, r *http.Request) {
		sid, err := r.Cookie(userSessionCookieName)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		session, ok := cfg.UserSessionStore.Get(sid.Value)
		if !ok {
			http.Error(w, "session expired", http.StatusUnauthorized)
			return
		}

		user, err := cfg.UserStore.Get(session.UserID)
		if err != nil {
			http.Error(w, "user not found", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"notes": user.(*User).Notes})
	})

	mux.HandleFunc("/notes/save", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		sid, err := r.Cookie(userSessionCookieName)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		session, ok := cfg.UserSessionStore.Get(sid.Value)
		if !ok {
			http.Error(w, "session expired", http.StatusUnauthorized)
			return
		}

		var data struct {
			Notes string `json:"notes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		user, err := cfg.UserStore.Get(session.UserID)
		if err != nil {
			http.Error(w, "user not found", http.StatusInternalServerError)
			return
		}

		u := user.(*User)
		u.Notes = data.Notes
		if err := cfg.UserStore.Update(u); err != nil {
			http.Error(w, "failed to save notes", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode("Notes Saved")
	})

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
