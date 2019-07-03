package secrets

import (
	"fmt"
	"testing"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func init() {
}

func TestSecretsSetup(t *testing.T) {
	fmt.Println("-----TestSecretsSetup-----")

	c := caddy.NewTestController("http", "")
	err := Setup(c)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	cfg := httpserver.GetConfig(c)
	mids := cfg.Middleware()
	if len(mids) > 0 {
		t.Error("Exptected setup to have failed")
	}

	c = caddy.NewTestController("http", "secrets")
	err = Setup(c)
	if err == nil {
		t.Errorf("Expected error 'open secrets: no such file or directory'")
	}
	cfg = httpserver.GetConfig(c)
	mids = cfg.Middleware()
	if len(mids) > 0 {
		t.Error("Exptected setup to have failed")
	}

	c = caddy.NewTestController("http", "secrets test.yml")
	err = Setup(c)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	cfg = httpserver.GetConfig(c)
	mids = cfg.Middleware()
	myHandler := mids[0](httpserver.EmptyNext)
	_, ok := myHandler.(SecretsHandler)
	if !ok {
		t.Errorf("Expected *SecretsHandler, got %T", myHandler)
	}

	c = caddy.NewTestController("http", "secrets test.yml something")
	err = Setup(c)
	if err == nil {
		t.Errorf("Expected error 'Secrets middleware received more arguments than expected'")
	}
}

func TestReadFile(t *testing.T) {
	fmt.Println("-----TestReadFile-----")

	c := caddy.NewTestController("http", "secrets missing.yml")
	err := Setup(c)
	if err == nil {
		t.Errorf("Expceted error `open missng.yml: no such file or directory`")
	}
	if SecretsMap == nil {
		t.Errorf("SecretsMap should've been initialized")
	}

	c = caddy.NewTestController("http", "secrets test.yml")
	err = Setup(c)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if SecretsMap == nil {
		t.Errorf("SecretsMap should've been initialized")
	}
}
