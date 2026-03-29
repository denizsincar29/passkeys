package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/go-webauthn/webauthn/webauthn"
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
		if err := json.Unmarshal(u.Credentials, &creds); err != nil {
			log.Printf("failed to unmarshal credentials for user %d: %v", u.ID, err)
		}
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

	b, err := json.Marshal(creds)
	if err != nil {
		log.Printf("failed to marshal credentials for user %d: %v", u.ID, err)
		return
	}
	u.Credentials = b
}
