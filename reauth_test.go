package reauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func emptyHandler(w http.ResponseWriter, r *http.Request) (int, error) {
	return http.StatusOK, nil
}

func TestSetup(t *testing.T) {
	test := `reauth {
				path /test
				simple username=password
			}`

	c := caddy.NewTestController("http", test)
	err := setup(c)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
}

func TestInvalidSetup(t *testing.T) {
	test := `reauth {
				path /test
				simple usernamepassword
			}`

	c := caddy.NewTestController("http", test)
	err := setup(c)
	if err == nil {
		t.Errorf("Expected error, got none")
	}
}

func TestMiddlewareProvider(t *testing.T) {
	test := `reauth {
				path /test
				except /test/foo
				except /test/bar
				simple username=password
			}`
	c := caddy.NewTestController("http", test)

	rules, _ := parseConfiguration(c)

	auth := &Reauth{
		rules: rules,
		next:  httpserver.HandlerFunc(emptyHandler),
	}

	req, _ := http.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	result, err := auth.ServeHTTP(rec, req)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if result != http.StatusOK {
		t.Errorf("Expected `%v` got `%v`", http.StatusOK, result)
	}

	req.URL.Path = "/test"
	result, err = auth.ServeHTTP(rec, req)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if result != http.StatusUnauthorized {
		t.Errorf("Expected `%v` got `%v`", http.StatusUnauthorized, result)
	}

	req.URL.Path = "/test/foo"
	result, err = auth.ServeHTTP(rec, req)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if result != http.StatusOK {
		t.Errorf("Expected `%v` got `%v`", http.StatusOK, result)
	}

	req.URL.Path = "/test"
	req.SetBasicAuth("username", "password")
	result, err = auth.ServeHTTP(rec, req)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if result != http.StatusOK {
		t.Errorf("Expected `%v` got `%v`", http.StatusOK, result)
	}
}
