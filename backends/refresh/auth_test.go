package refresh

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"gopkg.in/yaml.v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fellou89/caddy-cache"
	. "github.com/fellou89/caddy-secrets"
)

type claims struct {
	jwt.StandardClaims
	User  string                 `json:"user"`
	Email string                 `json:"email"`
	Scope map[string]interface{} `json:"scope"`
	Type  string                 `json:"type"`
	Roles []string               `json:"role"`
}

var token string

func init() {
	token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDQxMTY5NjEsImp0aSI6IjEwYTQ2ZjI5LWRhYWEtMTFlNy04MGViLTgwZTY1MDAxZjc2YSIsImlhdCI6MTUxMjU4MDk2MSwidXNlciI6InRlc3R1c2VyIiwiZW1haWwiOiJ0ZXN0dXNlckB0ZXN0ZG9tYWluLmNvbSIsInNjb3BlIjp7ImNpZHMiOiIqIn0sInR5cGUiOiJhY2Nlc3NfdG9rZW4iLCJyb2xlIjpbImFjY2Vzc19rZXlfdmFsaWRhdG9yIl19.gRQriovac1nKVuGEHfmJ4_rX-7TV191KOAEGVlK53Uw"
}

func authTokenCheck(w http.ResponseWriter, r *http.Request) {
	parser := jwt.Parser{}
	claims := claims{}

	if strings.Contains(r.URL.Path, "security_context") {
		r.ParseForm()
		accessToken := r.Form["access_token"][0]

		_, err := parser.ParseWithClaims(accessToken, &claims,
			func(token *jwt.Token) (interface{}, error) {
				return []byte("testkey"), nil
			},
		)

		if err != nil {
			w.WriteHeader(401)
			w.Write([]byte("{\"error\": \"" + err.Error() + "\"}"))
			return

		} else {
			err = claims.Valid()
			if err != nil {
				w.WriteHeader(401)
				w.Write([]byte("{\"message\": \"Forbidden\"}"))
				return
			}
		}

	} else { // get access token with refresh token
		r.ParseForm()
		token := r.Form["refresh_token"][0]
		_, err := parser.ParseWithClaims(token, &claims,
			func(token *jwt.Token) (interface{}, error) {
				return []byte("testkey"), nil
			},
		)

		if err != nil {
			w.WriteHeader(401)
			w.Write([]byte("{\"message\": \"Forbidden\"}"))

			return
		} else {
			err = claims.Valid()
			if err != nil {
				w.WriteHeader(401)
				w.Write([]byte("{\"message\": \"Forbidden\"}"))
				return
			}
		}
		w.WriteHeader(200)
		w.Write([]byte("{\"jwt_token\": \"" + token + "\"}"))
	}
	return
}

func TestAuthenticateSimple(t *testing.T) {
	fmt.Printf("\n-----TestAuthenticateSimple-----\n")

	SecretsMap = append(SecretsMap, yaml.MapItem{Key: "a", Value: token})

	srv := httptest.NewServer(http.HandlerFunc(authTokenCheck))
	defer func() {
		srv.Close()
	}()

	rf := &Refresh{
		refreshUrl:   srv.URL,
		refreshCache: cache.NewHTTPCache(),
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

	t.Log("Testing missing 'Bearer' prefix")
	r.Header.Set("Authorization", token)
	ok, err = rf.Authenticate(r)
	if err == nil {
		t.Errorf("Expected an error, didn't get one")
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing invalid jwt")
	r.Header.Set("Authorization", "Bearer Something")
	ok, err = rf.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing correct credentials")
	r.Header.Set("Authorization", "Bearer "+token)
	ok, err = rf.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if !ok {
		t.Error("Authenticate should have succeeded")
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

func TestAuthenticateConstructor(t *testing.T) {
	fmt.Printf("\n-----TestAuthenticateConstructor-----\n")

	SecretsMap = append(SecretsMap, yaml.MapItem{Key: "a", Value: "a"})

	url := "http://google.com"
	cacheConfig := &cache.Config{Path: "tmp", LockTimeout: time.Duration(5) * time.Minute}
	refreshCache := cache.NewHTTPCache()

	tests := []struct {
		desc   string
		config string
		expect *Refresh
		err    error
	}{
		{ // 1
			`Empty configuration`,
			``,
			nil,
			errors.New(`backend configuration has to be in form 'key1=value1,key2=..', but was `),
		},
		{ // 2
			`URL only configuration`,
			`url=http://google.com`,
			&Refresh{refreshUrl: url, timeout: DefaultTimeout},
			nil,
		},
		{ // 3
			`Invalid url configuration`,
			`url=!http://google.com`,
			nil,
			errors.New(`unable to parse url !http://google.com: parse !http://google.com: first path segment in URL cannot contain colon`),
		},
		{ // 4
			`With valid arguments`,
			`url=http://google.com,timeout=5s,skipverify=true,follow=true,cache_path=tmp,lock_timeout=5m`,
			&Refresh{refreshUrl: url, timeout: 5 * time.Second, insecureSkipVerify: true, followRedirects: true, cacheConfig: cacheConfig, refreshCache: refreshCache},
			nil,
		},
		{ // 5
			`With invalid timeout`,
			`url=http://google.com,timeout=5j`,
			nil,
			errors.New(`unable to parse timeout 5j: time: unknown unit j in duration 5j`),
		},
		{ // 6
			`With invalid insecure`,
			`url=http://google.com,skipverify=yesplease`,
			nil,
			errors.New(`unable to parse skipverify yesplease: strconv.ParseBool: parsing "yesplease": invalid syntax`),
		},
		{ // 7
			`With invalid follow`,
			`url=http://google.com,follow=yesplease`,
			nil,
			errors.New(`unable to parse follow yesplease: strconv.ParseBool: parsing "yesplease": invalid syntax`),
		},
		{ // 8
			`With valid arguments, missing url`,
			`timeout=5s,skipverify=true,follow=true`,
			nil,
			errors.New(`url is a required parameter`),
		},
		{ // 9
			`With pass cookies`,
			`url=http://google.com,cookies=true`,
			&Refresh{refreshUrl: url, timeout: DefaultTimeout, passCookies: true},
			nil,
		},
		{ // 10
			`With invalid pass cookies`,
			`url=http://google.com,cookies=yay`,
			nil,
			errors.New(`unable to parse cookies yay: strconv.ParseBool: parsing "yay": invalid syntax`),
		},
		{ // 11
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
			} else if tc.expect.refreshUrl == actual.refreshUrl &&
				tc.expect.refreshCache == actual.refreshCache &&
				tc.expect.cacheConfig.Path == actual.cacheConfig.Path {
				t.Errorf("%d Expected \n%+v got \n%+v", i+1, tc.expect, actual)
			}
		}
	}
}
