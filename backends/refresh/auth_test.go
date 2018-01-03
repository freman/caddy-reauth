package refresh

import (
	"crypto/x509"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/nicolasazrak/caddy-cache"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

type claims struct {
	jwt.StandardClaims
	User  string                 `json:"user"`
	Email string                 `json:"email"`
	Scope map[string]interface{} `json:"scope"`
	Type  string                 `json:"type"`
	Roles []string               `json:"role"`
}

func simplePasswordCheck(w http.ResponseWriter, r *http.Request) {
	parser := jwt.Parser{}
	claims := claims{}
	token := strings.Split(r.Header.Get("Authorization"), " ")[1]
	_, err := parser.ParseWithClaims(token, &claims,
		func(token *jwt.Token) (interface{}, error) {
			return []byte("testkey"), nil
		},
	)
	if err != nil {
		w.WriteHeader(401)
		return
	} else {
		err = claims.Valid()
		if err != nil {
			w.WriteHeader(401)
			return
		}
	}
	w.WriteHeader(200)
	return
}

func redirectPasswordCheck(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/auth", http.StatusSeeOther)
		return
	}
	simplePasswordCheck(w, r)
}

func TestAuthenticateSimple(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(simplePasswordCheck))
	ssrv := httptest.NewTLSServer(http.HandlerFunc(simplePasswordCheck))
	defer func() {
		srv.Close()
		ssrv.Close()
	}()

	ssrv.Config.ErrorLog = log.New(ioutil.Discard, "", 0) // ಠ_ಠ

	req, _ := http.NewRequest("GET", srv.URL, nil)
	sreq, _ := http.NewRequest("GET", ssrv.URL, nil)
	token := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDQxMTY5NjEsImp0aSI6IjEwYTQ2ZjI5LWRhYWEtMTFlNy04MGViLTgwZTY1MDAxZjc2YSIsImlhdCI6MTUxMjU4MDk2MSwidXNlciI6InRlc3R1c2VyIiwiZW1haWwiOiJ0ZXN0dXNlckB0ZXN0ZG9tYWluLmNvbSIsInNjb3BlIjp7ImNpZHMiOiIqIn0sInR5cGUiOiJhY2Nlc3NfdG9rZW4iLCJyb2xlIjpbImFjY2Vzc19rZXlfdmFsaWRhdG9yIl19.gRQriovac1nKVuGEHfmJ4_rX-7TV191KOAEGVlK53Uw"

	rf := &Refresh{
		refreshRequest: req,
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
	r.Header.Set("Authorization", "Bearer Something")
	ok, err = rf.Authenticate(r)
	if err == nil {
		t.Errorf("Expected an error, didn't get one")
	}
	if ok {
		t.Error("Authenticate should have failed")
	}
	req.Header.Del("Authorization")

	t.Log("Testing correct credentials")
	r.Header.Set("Authorization", token)
	ok, err = rf.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if !ok {
		t.Error("Authenticate should have succeeded")
	}

	t.Log("Testing over https with bad cert")
	r, _ = http.NewRequest("GET", "https://test.examples.com", nil)
	r.Header.Set("Authorization", token)
	rf.refreshRequest = sreq
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
	req, _ := http.NewRequest("GET", srv.URL, nil)
	token := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDQxMTY5NjEsImp0aSI6IjEwYTQ2ZjI5LWRhYWEtMTFlNy04MGViLTgwZTY1MDAxZjc2YSIsImlhdCI6MTUxMjU4MDk2MSwidXNlciI6InRlc3R1c2VyIiwiZW1haWwiOiJ0ZXN0dXNlckB0ZXN0ZG9tYWluLmNvbSIsInNjb3BlIjp7ImNpZHMiOiIqIn0sInR5cGUiOiJhY2Nlc3NfdG9rZW4iLCJyb2xlIjpbImFjY2Vzc19rZXlfdmFsaWRhdG9yIl19.gRQriovac1nKVuGEHfmJ4_rX-7TV191KOAEGVlK53Uw"

	rf := Refresh{
		refreshRequest: req,
		refreshCache:   cache.NewHTTPCache(),
		cacheConfig: &cache.Config{
			Path:        "tmp",
			LockTimeout: time.Duration(5) * time.Minute,
		},
		timeout: DefaultTimeout,
	}

	r, _ := http.NewRequest("GET", "https://test.example.com", nil)
	r.Header.Set("Authorization", token)
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

	r, _ = http.NewRequest("GET", "https://test.examples.com", nil)
	r.Header.Set("Authorization", token)
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
	cacheConfig := &cache.Config{Path: "tmp", LockTimeout: time.Duration(5) * time.Minute}

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
			`url=http://google.com,timeout=5s,skipverify=true,follow=true,cache_path=tmp,lock_timeout=5m`,
			&Refresh{refreshRequest: ref, timeout: 5 * time.Second, insecureSkipVerify: true, followRedirects: true, cacheConfig: cacheConfig},
			nil,
		}, {
			`With invalid timeout`,
			`url=http://google.com,timeout=5j`,
			nil,
			errors.New(`unable to parse timeout 5j: time: unknown unit j in duration 5j`),
		}, {
			`With invalid insecure`,
			`url=http://google.com,skipverify=yesplease`,
			nil,
			errors.New(`unable to parse skipverify yesplease: strconv.ParseBool: parsing "yesplease": invalid syntax`),
		}, {
			`With invalid follow`,
			`url=http://google.com,follow=yesplease`,
			nil,
			errors.New(`unable to parse follow yesplease: strconv.ParseBool: parsing "yesplease": invalid syntax`),
		}, {
			`With valid arguments, missing url`,
			`timeout=5s,skipverify=true,follow=true`,
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
		}, {
			`With invalid file lock timeout`,
			`url=http://google.com,lock_timeout=5j`,
			nil,
			errors.New(`unable to parse lock_timeout 5j: time: unknown unit j in duration 5j`),
		},
	}

	for i, tc := range tests {
		t.Logf("%d Testing configuration (%s)", i+1, tc.desc)
		be, err := constructor(tc.config)
		if tc.err != nil {
			if err == nil {
				t.Errorf("%d Expected error, got none", i+1)
			} else if err.Error() != tc.err.Error() {
				t.Errorf("%d Expected `%+v` got `%+v`", i+1, tc.err, err)
			}
		} else if err != nil {
			t.Errorf("%d Unexpected error `%+v`", i+1, err)
		}

		if tc.expect == nil {
			if be != nil {
				t.Errorf("%d Expected nil rules, got %+v", i+1, be)
			}
		} else {
			actual, ok := be.(*Refresh)
			if !ok {
				t.Errorf("%d Expected *Refresh, got %T", i+1, be)
			} else if !reflect.DeepEqual(tc.expect.refreshRequest, actual.refreshRequest) &&
				tc.expect.timeout == actual.timeout &&
				tc.expect.insecureSkipVerify == actual.insecureSkipVerify &&
				tc.expect.followRedirects == actual.followRedirects &&
				tc.expect.cacheConfig.Path == actual.cacheConfig.Path &&
				tc.expect.cacheConfig.LockTimeout == actual.cacheConfig.LockTimeout {
				t.Errorf("%d Expected \n%+v got \n%+v", i+1, tc.expect, actual)
			}
		}
	}
}
