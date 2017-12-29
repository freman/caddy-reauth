package refresh

import (
	"crypto/x509"
	"errors"
	"github.com/nicolasazrak/caddy-cache"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
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

func TestAuthenticateSimple(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(simplePasswordCheck))
	ssrv := httptest.NewTLSServer(http.HandlerFunc(simplePasswordCheck))
	defer func() {
		srv.Close()
		ssrv.Close()
	}()

	ssrv.Config.ErrorLog = log.New(ioutil.Discard, "", 0) // ಠ_ಠ

	sref, _ := http.NewRequest("GET", ssrv.URL, nil)
	ref, _ := http.NewRequest("GET", srv.URL, nil)

	rf := Refresh{
		refreshRequest: ref,
		refreshCache:   cache.NewHTTPCache(),
		cacheConfig: &cache.Config{
			Path:        "tmp",
			LockTimeout: time.Duration(5) * time.Minute,
		},
		timeout: DefaultTimeout,
	}

	t.Log("Testing no credentials")
	r, _ := http.NewRequest("GET", "https://test.example.com", nil)
	ok, err := rf.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing wrong credentials")
	r.SetBasicAuth("fred", "blogs")
	ok, err = rf.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing correct credentials")
	r.SetBasicAuth("bob-bcrypt", "secret")
	ok, err = rf.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if !ok {
		t.Error("Authenticate should have succeeded")
	}

	t.Log("Testing over https with bad cert")
	rf.refreshRequest = sref
	ok, err = rf.Authenticate(r)
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
	rf.insecureSkipVerify = true
	ok, err = rf.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if !ok {
		t.Error("Authenticate should have succeeded")
	}

}

func TestAuthenticateRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(redirectPasswordCheck))
	ref, _ := http.NewRequest("GET", srv.URL, nil)

	rf := Refresh{
		refreshRequest: ref,
		refreshCache:   cache.NewHTTPCache(),
		cacheConfig: &cache.Config{
			Path:        "tmp",
			LockTimeout: time.Duration(5) * time.Minute,
		},
		timeout: DefaultTimeout,
	}

	r, _ := http.NewRequest("GET", "https://test.example.com", nil)
	r.SetBasicAuth("bob-bcrypt", "secret")

	ok, err := rf.Authenticate(r)
	if err == nil {
		t.Error("Expected an error, didn't get one")
	} else if err.Error() != "Get /auth: follow redirects disabled" {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should not have succeeded")
	}

	rf.followRedirects = true

	ok, err = rf.Authenticate(r)
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
	ref, _ := http.NewRequest("GET", srv.URL, nil)

	rf := Refresh{
		refreshRequest: ref,
		refreshCache:   cache.NewHTTPCache(),
		cacheConfig: &cache.Config{
			Path:        "tmp",
			LockTimeout: time.Duration(5) * time.Minute,
		},
		timeout:     DefaultTimeout,
		passCookies: true,
	}

	t.Log("Testing no credentials")
	r, _ := http.NewRequest("GET", "https://test.example.com", nil)
	ok, err := rf.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing wrong credentials")
	r.AddCookie(&http.Cookie{Name: "test", Value: "trustnoone"})
	ok, err = rf.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing correct credentials")
	r, _ = http.NewRequest("GET", "https://test.example.com", nil)
	r.AddCookie(&http.Cookie{Name: "test", Value: "trustme"})
	ok, err = rf.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if !ok {
		t.Error("Authenticate should have succeeded")
	}
}

func TestAuthenticateConstructor(t *testing.T) {
	ref, _ := http.NewRequest("GET", "http://google.com", nil)

	tests := []struct {
		desc   string
		config string
		expect *Refresh
		err    error
	}{
		{
			`Empty configuration`,
			``,
			nil,
			errors.New(`backend configuration has to be in form 'key1=value1,key2=..', but was `),
		}, {
			`URL only configuration`,
			`url=http://google.com`,
			&Refresh{refreshRequest: ref, timeout: DefaultTimeout},
			nil,
		}, {
			`Invalid url configuration`,
			`url=!http://google.com`,
			nil,
			errors.New(`unable to parse url !http://google.com: parse !http://google.com: first path segment in URL cannot contain colon`),
		}, {
			`With valid arguments`,
			`url=http://google.com,timeout=5s,insecure=true,follow=true`,
			&Refresh{refreshRequest: ref, timeout: 5 * time.Second, insecureSkipVerify: true, followRedirects: true},
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
			&Refresh{refreshRequest: ref, timeout: DefaultTimeout, passCookies: true},
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
			actual, ok := be.(*Refresh)
			if !ok {
				t.Errorf("Expected *Upstream, got %T", be)
			} else if !reflect.DeepEqual(tc.expect, actual) {
				t.Errorf("Expected %v got %v", tc.expect, actual)
			}
		}
	}
}
