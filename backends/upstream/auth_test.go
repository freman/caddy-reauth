package upstream

import (
	"crypto/x509"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"testing"
	"time"
)

func simplePasswordCheck(w http.ResponseWriter, r *http.Request) {
	u, p, k := r.BasicAuth()
	if !k {
		w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
	}

	if !(u == "bob-bcrypt" && p == "secret") {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
}

func redirectPasswordCheck(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/auth", http.StatusSeeOther)
		return
	}

	u, p, k := r.BasicAuth()
	if !k {
		w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
	}

	if !(u == "bob-bcrypt" && p == "secret") {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
}

func simpleCookieCheck(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("test")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if c == nil || c.Value != "trustme" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
}

func cookieRedirectCheck(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		c, err := r.Cookie("test")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if c == nil || c.Value != "trustme" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		return
	}
}

func TestAuthenticateSimple(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(simplePasswordCheck))
	ssrv := httptest.NewTLSServer(http.HandlerFunc(simplePasswordCheck))
	defer func() {
		srv.Close()
		ssrv.Close()
	}()

	ssrv.Config.ErrorLog = log.New(ioutil.Discard, "", 0) // ಠ_ಠ

	uri, _ := url.Parse(srv.URL)
	suri, _ := url.Parse(ssrv.URL)

	us := Upstream{
		url:     uri,
		timeout: DefaultTimeout,
	}

	t.Log("Testing no credentials")
	r, _ := http.NewRequest("GET", "https://test.example.com", nil)
	ok, err := us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing wrong credentials")
	r.SetBasicAuth("fred", "blogs")
	ok, err = us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing correct credentials")
	r.SetBasicAuth("bob-bcrypt", "secret")
	ok, err = us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if !ok {
		t.Error("Authenticate should have succeeded")
	}

	t.Log("Testing over https with bad cert")
	us.url = suri
	ok, err = us.Authenticate(r)
	if err == nil {
		t.Errorf("Expected an error, didn't get one")
	} else {
		uerr, ok := err.(*url.Error)
		if !ok {
			t.Errorf("Unexpected error `%v`", err)
		} else if _, ok := uerr.Err.(x509.UnknownAuthorityError); !ok {
			t.Errorf("Unexpected error `%v`", err)
		}
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing over https with skipverify")
	us.insecureSkipVerify = true
	ok, err = us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if !ok {
		t.Error("Authenticate should have succeeded")
	}

}

func TestAuthenticateRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(redirectPasswordCheck))
	uri, _ := url.Parse(srv.URL)

	us := Upstream{
		url:     uri,
		timeout: DefaultTimeout,
	}

	r, _ := http.NewRequest("GET", "https://test.example.com", nil)
	r.SetBasicAuth("bob-bcrypt", "secret")

	ok, err := us.Authenticate(r)
	if err == nil {
		t.Error("Expected an error, didn't get one")
	} else if err.Error() != "Get /auth: follow redirects disabled" {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should not have succeeded")
	}

	us.followRedirects = true

	ok, err = us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if !ok {
		t.Error("Authenticate should have succeeded")
	}
}

func TestAuthenticateCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(simpleCookieCheck))
	defer srv.Close()

	uri, _ := url.Parse(srv.URL)

	us := Upstream{
		url:         uri,
		timeout:     DefaultTimeout,
		passCookies: true,
	}

	t.Log("Testing no credentials")
	r, _ := http.NewRequest("GET", "https://test.example.com", nil)
	ok, err := us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing wrong credentials")
	r.AddCookie(&http.Cookie{Name: "test", Value: "trustnoone"})
	ok, err = us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing correct credentials")
	r, _ = http.NewRequest("GET", "https://test.example.com", nil)
	r.AddCookie(&http.Cookie{Name: "test", Value: "trustme"})
	ok, err = us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if !ok {
		t.Error("Authenticate should have succeeded")
	}
}

func TestAuthenticateCookieRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(cookieRedirectCheck))
	defer srv.Close()

	uri, _ := url.Parse(srv.URL)

	us := Upstream{
		url:             uri,
		timeout:         DefaultTimeout,
		followRedirects: true,
		passCookies:     true,
		match:           regexp.MustCompile("login"),
	}

	t.Log("Testing no credentials")
	r, _ := http.NewRequest("GET", "https://test.example.com", nil)
	ok, err := us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing wrong credentials")
	r.AddCookie(&http.Cookie{Name: "test", Value: "trustnoone"})
	ok, err = us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing correct credentials")
	r, _ = http.NewRequest("GET", "https://test.example.com", nil)
	r.AddCookie(&http.Cookie{Name: "test", Value: "trustme"})
	ok, err = us.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if !ok {
		t.Error("Authenticate should have succeeded")
	}
}

func TestAuthenticateConstructor(t *testing.T) {
	tests := []struct {
		desc   string
		config string
		expect *Upstream
		err    error
	}{
		{
			`Empty configuration`,
			``,
			nil,
			errors.New(`Unable to parse options string, missing pair`),
		}, {
			`URL only configuration`,
			`url=http://google.com`,
			&Upstream{url: &url.URL{Scheme: `http`, Host: `google.com`}, timeout: DefaultTimeout},
			nil,
		}, {
			`Invalid url configuration`,
			`url=!http://google.com`,
			nil,
			errors.New(`unable to parse url !http://google.com: parse !http://google.com: first path segment in URL cannot contain colon`),
		}, {
			`With valid arguments`,
			`url=http://google.com,timeout=5s,insecure=true,follow=true`,
			&Upstream{url: &url.URL{Scheme: `http`, Host: `google.com`}, timeout: 5 * time.Second, insecureSkipVerify: true, followRedirects: true},
			nil,
		}, {
			`With invalid timeout`,
			`url=http://google.com,timeout=5j`,
			nil,
			errors.New(`unable to parse timeout 5j: time: unknown unit j in duration 5j`),
		}, {
			`With invalid insecure`,
			`url=http://google.com,insecure=yesplease`,
			nil,
			errors.New(`unable to parse insecure yesplease: strconv.ParseBool: parsing "yesplease": invalid syntax`),
		}, {
			`With invalid follow`,
			`url=http://google.com,follow=yesplease`,
			nil,
			errors.New(`unable to parse follow yesplease: strconv.ParseBool: parsing "yesplease": invalid syntax`),
		}, {
			`With valid arguments, missing url`,
			`timeout=5s,insecure=true,follow=true`,
			nil,
			errors.New(`url is a required parameter`),
		}, {
			`With pass cookies`,
			`url=http://google.com,cookies=true`,
			&Upstream{url: &url.URL{Scheme: `http`, Host: `google.com`}, timeout: DefaultTimeout, passCookies: true},
			nil,
		}, {
			`With invalid pass cookies`,
			`url=http://google.com,cookies=yay`,
			nil,
			errors.New(`unable to parse cookies yay: strconv.ParseBool: parsing "yay": invalid syntax`),
		},
	}

	for i, tc := range tests {
		t.Logf("Testing configuration %d (%s)", i+1, tc.desc)
		be, err := constructor(tc.config)
		if tc.err != nil {
			if err == nil {
				t.Error("Expected error, got none")
			} else if err.Error() != tc.err.Error() {
				t.Errorf("Expected `%v` got `%v`", tc.err, err)
			}
		} else if err != nil {
			t.Errorf("Unexpected error `%v`", err)
		}

		if tc.expect == nil {
			if be != nil {
				t.Errorf("Expected nil rules, got %v", be)
			}
		} else {
			actual, ok := be.(*Upstream)
			if !ok {
				t.Errorf("Expected *Upstream, got %T", be)
			} else if !reflect.DeepEqual(tc.expect, actual) {
				t.Errorf("Expected %v got %v", tc.expect, actual)
			}
		}
	}
}
