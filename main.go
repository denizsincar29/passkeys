package main

import (
	"log"
	"net/http"
	"os"

	"github.com/egregors/passkey"
)

func main() {
	appDomain := os.Getenv("APP_DOMAIN")
	if appDomain == "" {
		appDomain = "localhost"
	}

	isLocal := appDomain == "localhost"

	cfg := passkey.Config{
		RPID:          appDomain,
		RPDisplayName: "Passkey Demo",
	}

	if isLocal {
		cfg.RPOrigins = []string{"http://localhost:8080"}
	} else {
		cfg.RPOrigins = []string{"https://" + appDomain}
	}

	// 🔥 создаём passkey handler
	pk, err := passkey.New(cfg, passkey.DefaultMemoryStore())
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// =========================
	// AUTH ROUTES (ВСЁ ГОТОВО)
	// =========================
	mux.Handle("/auth/", http.StripPrefix("/auth", pk.Handler()))

	// =========================
	// UI
	// =========================
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "templates/index.html")
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Println("running on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
