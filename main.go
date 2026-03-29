package main

import (
	"encoding/json"
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

	// Internal webauthn instance from passkey lib is not exported, but we have our own in cfg.
	// We need to use it to support discovery login.
	wa, err := webauthn.New(cfg.WebauthnConfig)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	pk.MountRoutes(mux, "/auth/")

	// Override/Add discovery login and registration routes
	mux.HandleFunc("/auth/passkey/registerFinish", func(w http.ResponseWriter, r *http.Request) {
		sid, err := r.Cookie("asid")
		if err != nil {
			http.Error(w, "session not found", http.StatusBadRequest)
			return
		}

		session, ok := cfg.AuthSessionStore.Get(sid.Value)
		if !ok {
			http.Error(w, "session not found", http.StatusBadRequest)
			return
		}

		user, err := cfg.UserStore.Get(session.UserID)
		if err != nil {
			http.Error(w, "user not found", http.StatusInternalServerError)
			return
		}

		credential, err := wa.FinishRegistration(user, *session, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		user.PutCredential(*credential)
		cfg.UserStore.Update(user)
		cfg.AuthSessionStore.Delete(sid.Value)

		// Automatically log in after registration
		t, _ := cfg.UserSessionStore.Create(passkey.UserSessionData{
			UserID:  user.WebAuthnID(),
			Expires: time.Now().Add(time.Hour),
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "usid",
			Value:    t,
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode("Registration Success")
	})

	mux.HandleFunc("/auth/passkey/loginBegin", func(w http.ResponseWriter, r *http.Request) {
		var u struct {
			Username string `json:"username"`
		}
		_ = json.NewDecoder(r.Body).Decode(&u)

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
			// Discovery login
			options, session, err = wa.BeginDiscoverableLogin()
		}

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		t, _ := cfg.AuthSessionStore.Create(*session)
		http.SetCookie(w, &http.Cookie{
			Name:     "asid",
			Value:    t,
			Path:     "/",
			MaxAge:   300,
			HttpOnly: true,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(options)
	})

	mux.HandleFunc("/auth/passkey/loginFinish", func(w http.ResponseWriter, r *http.Request) {
		sid, err := r.Cookie("asid")
		if err != nil {
			http.Error(w, "session not found", http.StatusBadRequest)
			return
		}

		session, ok := cfg.AuthSessionStore.Get(sid.Value)
		if !ok {
			http.Error(w, "session not found", http.StatusBadRequest)
			return
		}

		var user *User
		var credential *webauthn.Credential

		if len(session.UserID) > 0 {
			u, err := cfg.UserStore.Get(session.UserID)
			if err != nil {
				http.Error(w, "user not found", http.StatusInternalServerError)
				return
			}
			user = u.(*User)
			credential, err = wa.FinishLogin(user, *session, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			// Discovery login
			userHandler := func(rawID, userHandle []byte) (webauthn.User, error) {
				u, err := cfg.UserStore.Get(userHandle)
				if err != nil {
					return nil, err
				}
				return u.(*User), nil
			}
			// Use FinishPasskeyLogin which is designed for discovery (usernameless)
			waUser, cred, err := wa.FinishPasskeyLogin(userHandler, *session, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			user = waUser.(*User)
			credential = cred
		}

		user.PutCredential(*credential)
		cfg.UserStore.Update(user)
		cfg.AuthSessionStore.Delete(sid.Value)

		t, _ := cfg.UserSessionStore.Create(passkey.UserSessionData{
			UserID:  user.WebAuthnID(),
			Expires: time.Now().Add(time.Hour),
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "usid",
			Value:    t,
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode("Login Success")
	})

	mux.HandleFunc("/notes/get", func(w http.ResponseWriter, r *http.Request) {
		sid, err := r.Cookie("usid")
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
		json.NewEncoder(w).Encode(map[string]string{"notes": user.(*User).Notes})
	})

	mux.HandleFunc("/notes/save", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		sid, err := r.Cookie("usid")
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
		cfg.UserStore.Update(u)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode("Notes Saved")
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
