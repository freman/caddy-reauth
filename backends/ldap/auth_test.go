package ldap

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

func TestAuthLDAP(t *testing.T) {
	cfg, err := json.Marshal(LDAP{
		Host:         os.Getenv("CADDY_LDAP_HOST"),
		BindUsername: os.Getenv("CADDY_LDAP_BIND_USERNAME"),
		BindPassword: os.Getenv("CADDY_LDAP_BIND_PASSWORD"),
		Base:         os.Getenv("CADDY_LDAP_BASE"),
		Filter:       os.Getenv("CADDY_LDAP_FILTER"),
	})
	B, err := constructor(string(cfg))
	if err != nil {
		if os.Getenv("CADDY_LDAP_HOST") == "" {
			t.Skip(err)
		}
		t.Fatal(err)
	}

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	us, pw := os.Getenv("CADDY_LDAP_USER"), os.Getenv("CADDY_LDAP_PASSW")
	req.SetBasicAuth(us, pw)
	ok, err := B.Authenticate(req)
	t.Logf("%s: %v", us, ok)
	if err != nil {
		if us == "" {
			t.Skip(err)
		}
		t.Fatal(err)
	}
}
