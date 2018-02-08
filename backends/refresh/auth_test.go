package refresh

import (
	"bytes"
	"errors"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/fellou89/caddy-cache"
	. "github.com/fellou89/caddy-secrets"
	"github.com/satori/go.uuid"
)

type Claims struct {
	jwt.StandardClaims
	User  string   `json:"user"`
	Email string   `json:"email"`
	Scope []string `json:"scope"`
	Type  string   `json:"type"`
	Roles []string `json:"role"`
}

var token string

func init() {
	cmd := exec.Command("/bin/sh", "-c", "go run auth_endpoint/test.go")
	var out bytes.Buffer
	cmd.Stdout = &out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	go func() {
		err := cmd.Run()
		if err != nil {
			fmt.Println(err.Error() + " : " + stderr.String())
		}
	}()
	time.Sleep(10 * time.Second)

	refreshToken, err := GenerateAccessToken()

	client := &http.Client{}

	req, err := http.NewRequest("GET", "http://localhost:8081/pre_prod/aqfer/auth/v1/access_token?grant_type=refresh_token&refresh_token="+refreshToken, nil)
	if err != nil {
		fmt.Println(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	containerExp := regexp.MustCompile(".*\"jwt_token\": \"([A-Za-z0-9\\.\\-_]+)\",.*")

	match := containerExp.FindStringSubmatch(string(body))
	token = match[1]
	cmd.Process.Kill()
}

func GenerateAccessToken() (string, error) {
	now := time.Now().Unix()
	uuid, _ := uuid.NewV1()
	claims := Claims{
		StandardClaims: jwt.StandardClaims{
			Id:        uuid.String(),
			IssuedAt:  now,
			ExpiresAt: now + 7200,
		},
		User:  "test",
		Email: "test@user.com",
		Scope: []string{"asdf"},
		Type:  "access_token",
		Roles: []string{},
	}
	tkn, err := mkJwtToken("testkey", claims)
	if err == nil {
		return tkn, nil
	}
	return "", err
}

func mkJwtToken(key string, claims Claims) (string, error) {
	tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tkn.SignedString([]byte(key))
}

func authTokenCheck(w http.ResponseWriter, r *http.Request) {
	parser := jwt.Parser{}
	claims := Claims{}

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
