package main

import (
	"encoding/json"
	"fmt"

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
