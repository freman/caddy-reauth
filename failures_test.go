package reauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBasicAuthFailure(t *testing.T) {
	c := failureHandlers["basicauth"]
	if c == nil {
		t.Fatal("constructor should not be nil")
	}

	_, err := c("relm")
	if err == nil {
		t.Fatal("expected error")
	}

	f, err := c("")
	if err != nil {
		t.Fatal("empty string shouldn't fail")
	}
	if f == nil {
		t.Fatal("f shouldn't be nil")
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Host = "example.org"
	s, err := f.Handle(w, r)
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if s != http.StatusUnauthorized {
		t.Errorf("expected %d got %d", http.StatusUnauthorized, s)
	}

	if expect, got := `Basic realm="example.org"`, w.Header().Get("WWW-Authenticate"); expect != got {
		t.Errorf("expected %s got %s", expect, got)
	}

	f, err = c("realm=foo.bar")
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	w = httptest.NewRecorder()
	s, err = f.Handle(w, r)
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if s != http.StatusUnauthorized {
		t.Errorf("expected %d got %d", http.StatusUnauthorized, s)
	}

	if expect, got := `Basic realm="foo.bar"`, w.Header().Get("WWW-Authenticate"); expect != got {
		t.Errorf("expected %s got %s", expect, got)
	}
}
func TestRedirectAuthFailure(t *testing.T) {
	c := failureHandlers["redirect"]
	if c == nil {
		t.Fatal("constructor should not be nil")
	}

	errCfgs := []string{
		"target=://example.com,code=303",
		//"target=http://example.com,code", TODO: Fix this in the backend parser this is bad mkay
		"target=http://example.com,code=red",
	}
	for _, ec := range errCfgs {
		_, err := c(ec)
		if err == nil {
			t.Fatal("expected error")
		}
	}

	f, err := c("")
	if err == nil {
		t.Fatal("empty string should fail")
	}

	f, err = c("code=301")
	if err == nil {
		t.Fatal("target should be required")
	}

	f, err = c("target=http://example.com")
	if err != nil {
		t.Fatal("unexpected error", err.Error())
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	s, err := f.Handle(w, r)
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if s != http.StatusFound {
		t.Errorf("expected %d got %d", http.StatusFound, s)
	}
	if expect, got := `http://example.com`, w.Header().Get("Location"); expect != got {
		t.Errorf("expected %s got %s", expect, got)
	}

	f, err = c("target=http://example.com,code=303")
	if err != nil {
		t.Fatal("unexpected error", err.Error())
	}

	w = httptest.NewRecorder()
	s, err = f.Handle(w, r)

	if s != http.StatusSeeOther {
		t.Errorf("expected %d got %d", http.StatusSeeOther, s)
	}
	if expect, got := `http://example.com`, w.Header().Get("Location"); expect != got {
		t.Errorf("expected %s got %s", expect, got)
	}
}

func TestRedirectAuthFailureTemplate(t *testing.T) {
	c := failureHandlers["redirect"]
	if c == nil {
		t.Fatal("constructor should not be nil")
	}

	f, err := c("target=http://example.com/auth?redir={uri}")
	if err != nil {
		t.Fatal("unexpected error", err.Error())
	}
	r, _ := http.NewRequest(http.MethodGet, "http://example.com/deep/pages?are=deep", nil)
	w := httptest.NewRecorder()
	_, err = f.Handle(w, r)

	if expect, got := `http://example.com/auth?redir=%2Fdeep%2Fpages%3Fare%3Ddeep`, w.Header().Get("Location"); expect != got {
		t.Errorf("expected %s got %s", expect, got)
	}

	r.Host = "example.org"
	w = httptest.NewRecorder()
	_, err = f.Handle(w, r)

	if expect, got := `http://example.com/auth?redir=http%3A%2F%2Fexample.org%2Fdeep%2Fpages%3Fare%3Ddeep`, w.Header().Get("Location"); expect != got {
		t.Errorf("expected %s got %s", expect, got)
	}

	r.Header.Add("X-Forwarded-Proto", "https")
	w = httptest.NewRecorder()
	_, err = f.Handle(w, r)

	if expect, got := `http://example.com/auth?redir=https%3A%2F%2Fexample.org%2Fdeep%2Fpages%3Fare%3Ddeep`, w.Header().Get("Location"); expect != got {
		t.Errorf("expected %s got %s", expect, got)
	}

	f, err = c("target=/auth?redir={uri}")
	if err != nil {
		t.Fatal("unexpected error", err.Error())
	}
	r, _ = http.NewRequest(http.MethodGet, "http://example.com/deep/pages?are=deep", nil)
	w = httptest.NewRecorder()
	_, err = f.Handle(w, r)

	if expect, got := `/auth?redir=%2Fdeep%2Fpages%3Fare%3Ddeep`, w.Header().Get("Location"); expect != got {
		t.Errorf("expected %s got %s", expect, got)
	}

	r.Host = "example.org"
	w = httptest.NewRecorder()
	_, err = f.Handle(w, r)

	if expect, got := `/auth?redir=%2Fdeep%2Fpages%3Fare%3Ddeep`, w.Header().Get("Location"); expect != got {
		t.Errorf("expected %s got %s", expect, got)
	}

	r.Header.Add("X-Forwarded-Proto", "https")
	w = httptest.NewRecorder()
	_, err = f.Handle(w, r)

	if expect, got := `/auth?redir=%2Fdeep%2Fpages%3Fare%3Ddeep`, w.Header().Get("Location"); expect != got {
		t.Errorf("expected %s got %s", expect, got)
	}
}

func TestCodeAuthFailure(t *testing.T) {
	c := failureHandlers["status"]
	if c == nil {
		t.Fatal("constructor should not be nil")
	}

	errCfgs := []string{
		"code",
		"code=red",
	}
	for _, ec := range errCfgs {
		_, err := c(ec)
		if err == nil {
			t.Fatal("expected error")
		}
	}

	f, err := c("")
	if err != nil {
		t.Fatal("empty string shouldn't fail")
	}
	if f == nil {
		t.Fatal("f shouldn't be nil")
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	s, err := f.Handle(w, r)
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}
	if s != http.StatusUnauthorized {
		t.Errorf("expected %d got %d", http.StatusFound, s)
	}

	f, err = c("code=418")
	if err != nil {
		t.Fatal("unexpected error", err.Error())
	}

	w = httptest.NewRecorder()
	s, err = f.Handle(w, r)

	if s != http.StatusTeapot {
		t.Errorf("expected %d got %d", http.StatusTeapot, s)
	}
}
