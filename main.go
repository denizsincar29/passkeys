package main

import (
	"log"
	"net/http"
	"os"

	"github.com/egregors/passkey"
	"github.com/glebarez/sqlite"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Printf("no .env file found, using environment variables")
	}

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
		log.Fatalf("failed to create database directory: %v", err)
	}
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
