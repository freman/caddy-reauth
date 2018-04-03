package refresh

import (
	// "bytes"
	// "io/ioutil"
	// "os/exec"
	// "regexp"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/allegro/bigcache"
	"github.com/dgrijalva/jwt-go"
	// "github.com/satori/go.uuid"
	"github.com/startsmartlabs/caddy-secrets"
	"gopkg.in/yaml.v2"
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
	token = "asdf"
}

// 	cmd := exec.Command("/bin/sh", "-c", "go run auth_endpoint/test.go")
// 	var out bytes.Buffer
// 	cmd.Stdout = &out
// 	var stderr bytes.Buffer
// 	cmd.Stderr = &stderr
//
// 	go func() {
// 		err := cmd.Run()
// 		if err != nil {
// 			fmt.Println(err.Error() + " : " + stderr.String())
// 		}
// 	}()
// 	time.Sleep(10 * time.Second)
//
// 	refreshToken, err := GenerateAccessToken()
//
// 	client := &http.Client{}
//
// 	req, err := http.NewRequest("GET", "http://localhost:8081/pre_prod/aqfer/auth/v1/access_token?grant_type=refresh_token&refresh_token="+refreshToken, nil)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
//
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	defer resp.Body.Close()
//
// 	body, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
//
// 	containerExp := regexp.MustCompile(".*\"jwt_token\": \"([A-Za-z0-9\\.\\-_]+)\",.*")
//
// 	match := containerExp.FindStringSubmatch(string(body))
// 	token = match[1]
// 	cmd.Process.Kill()
// }

// func GenerateAccessToken() (string, error) {
// 	now := time.Now().Unix()
// 	uuid, _ := uuid.NewV1()
// 	claims := Claims{
// 		StandardClaims: jwt.StandardClaims{
// 			Id:        uuid.String(),
// 			IssuedAt:  now,
// 			ExpiresAt: now + 7200,
// 		},
// 		User:  "test",
// 		Email: "test@user.com",
// 		Scope: []string{"asdf"},
// 		Type:  "access_token",
// 		Roles: []string{},
// 	}
// 	tkn, err := mkJwtToken("testkey", claims)
// 	if err == nil {
// 		return tkn, nil
// 	}
// 	return "", err
// }

// func mkJwtToken(key string, claims Claims) (string, error) {
// 	tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	return tkn.SignedString([]byte(key))
// }

func authTokenCheck(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	if strings.Contains(r.URL.String(), "return_query") {
		w.WriteHeader(200)
		w.Write([]byte(r.URL.String()))
		return

	} else if strings.Contains(r.URL.String(), "return_form") {
		bodyBytes, _ := ioutil.ReadAll(r.Body)
		w.WriteHeader(200)
		w.Write(bodyBytes)
		return

	} else if strings.Contains(r.URL.String(), "return_host") {
		w.WriteHeader(200)
		w.Write([]byte(r.Host))
		return

	} else if strings.Contains(r.URL.String(), "return_cookies") {
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf("%+v", r.Cookies())))
		return

	} else if strings.Contains(r.URL.String(), "return_headers") {
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf("%+v", r.Header)))
		return

	}
	// if err != nil {
	// 	w.WriteHeader(401)
	// 	w.Write([]byte("{\"error\": \"" + err.Error() + "\"}"))
	// 	return

	// } else if err != nil {
	// 	w.WriteHeader(401)
	// 	w.Write([]byte("{\"message\": \"Forbidden\"}"))
	// 	return

	// } else {
	// 	err = claims.Valid()
	// 	if err != nil {
	// 		w.WriteHeader(401)
	// 		w.Write([]byte("{\"message\": \"Forbidden\"}"))
	// 		return
	// 	}
	// }

	w.WriteHeader(200)
	w.Write([]byte("{\"jwt_token\": \"" + token + "\"}"))
	return
}

func TestAuthenticateSimple(t *testing.T) {
	fmt.Printf("\n-----TestAuthenticateSimple-----\n")

	reauth := yaml.MapSlice{}
	reauth = append(reauth, yaml.MapItem{
		Key:   "client_authorization",
		Value: true,
	})
	secrets.SecretsMap = append(secrets.SecretsMap, yaml.MapItem{
		Key:   "reauth",
		Value: reauth,
	})

	srv := httptest.NewServer(http.HandlerFunc(authTokenCheck))
	defer func() {
		srv.Close()
	}()

	cache, _ := bigcache.NewBigCache(bigcache.DefaultConfig(time.Minute))
	rf := &Refresh{
		refreshUrl:   srv.URL,
		refreshCache: cache,
		timeout:      DefaultTimeout,
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

	reauth := yaml.MapSlice{}
	reauth = append(reauth, yaml.MapItem{
		Key:   "client_authorization",
		Value: true,
	})
	secrets.SecretsMap = append(secrets.SecretsMap, yaml.MapItem{
		Key:   "reauth",
		Value: reauth,
	})

	url := "http://google.com"
	refreshCache, _ := bigcache.NewBigCache(bigcache.DefaultConfig(time.Minute))

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
			`url=http://google.com,timeout=5s,skipverify=true,follow=true,filewindow=1m`,
			&Refresh{refreshUrl: url, timeout: 5 * time.Second, insecureSkipVerify: true, followRedirects: true, refreshCache: refreshCache},
			nil,
		},
		{ // 5
			`With invalid timeout`,
			`url=http://google.com,timeout=5j`,
			nil,
			errors.New(`time: unknown unit j in duration 5j`),
		},
		{ // 6
			`With invalid insecure`,
			`url=http://google.com,skipverify=yesplease`,
			nil,
			errors.New(`strconv.ParseBool: parsing "yesplease": invalid syntax`),
		},
		{ // 7
			`With invalid follow`,
			`url=http://google.com,follow=yesplease`,
			nil,
			errors.New(`strconv.ParseBool: parsing "yesplease": invalid syntax`),
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
			errors.New(`strconv.ParseBool: parsing "yay": invalid syntax`),
		},
		{ // 11
			`With invalid filewindow duration`,
			`url=http://google.com,lifewindow=5j`,
			nil,
			errors.New(`time: unknown unit j in duration 5j`),
		},
		{ // 12
			`With invalid cleanwindow duration`,
			`url=http://google.com,cleanwindow=5j`,
			nil,
			errors.New(`time: unknown unit j in duration 5j`),
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
				tc.expect.refreshCache == actual.refreshCache {
				t.Errorf("%d Expected \n%+v got \n%+v", i+1, tc.expect, actual)
			}
		}
	}
}

func TestRefreshRequestObject(t *testing.T) {
	fmt.Printf("\n-----TestRefreshRequestObject-----\n")

	reauth := yaml.MapSlice{}
	reauth = append(reauth, yaml.MapItem{
		Key:   "client_authorization",
		Value: true,
	})
	secrets.SecretsMap = append(secrets.SecretsMap, yaml.MapItem{
		Key:   "reauth",
		Value: reauth,
	})

	ssrv := httptest.NewTLSServer(http.HandlerFunc(authTokenCheck))
	srv := httptest.NewServer(http.HandlerFunc(authTokenCheck))
	defer func() {
		ssrv.Close()
		srv.Close()
	}()
	uri, _ := url.Parse(srv.URL)
	suri, _ := url.Parse(ssrv.URL)

	refreshCache, _ := bigcache.NewBigCache(bigcache.DefaultConfig(time.Minute))
	refresh := &Refresh{refreshUrl: uri.String(), timeout: 5 * time.Second, passCookies: true, insecureSkipVerify: true, followRedirects: true, refreshCache: refreshCache}

	c := &http.Client{Timeout: refresh.timeout}
	r, _ := http.NewRequest("GET", "http://test.example.com", nil)

	t.Log("Testing Endpoint with unhandled method")
	_, err := refresh.refreshRequestObject(c, r, Endpoint{Method: "PUT"}, map[string]string{})
	if err == nil {
		t.Errorf("Expected error got none")
	}

	t.Log("Testing Endpoint with GET method")
	_, err = refresh.refreshRequestObject(c, r, Endpoint{Method: "GET"}, map[string]string{})
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	t.Log("Testing Endpoint url used when set")
	refresh.refreshUrl = suri.String()
	host, err := refresh.refreshRequestObject(c, r, Endpoint{Method: "GET", Url: uri.String() + "/return_host"}, map[string]string{})
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
	if string(host) == uri.String() {
		t.Errorf("Endpoint request did not use the uri host that was set")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing GET Endpoint had data encoded into query string")
	refresh.refreshUrl += "/return_query"
	query, err := refresh.refreshRequestObject(c, r, Endpoint{
		Method: "GET",
		Data:   []DataObject{DataObject{Key: "one", Value: "asdf"}, DataObject{Key: "two", Value: "fdsa"}},
	}, map[string]string{})
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
	if string(query) != "/return_query?one=asdf&two=fdsa" {
		t.Errorf("Data was not properly encoded")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing Endpoint with POST method")
	_, err = refresh.refreshRequestObject(c, r, Endpoint{Method: "POST"}, map[string]string{})
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}

	t.Log("Testing POST Endpoint had data encoded into request form")
	refresh.refreshUrl += "/return_form"
	form, err := refresh.refreshRequestObject(c, r, Endpoint{
		Method: "POST",
		Data:   []DataObject{DataObject{Key: "one", Value: "asdf"}, DataObject{Key: "two", Value: "fdsa"}},
	}, map[string]string{})
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
	if string(form) != "one=asdf&two=fdsa" {
		t.Errorf("Data was not properly encoded")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing Endpoint data replaces references with input values")
	refresh.refreshUrl += "/return_form"
	form, err = refresh.refreshRequestObject(c, r, Endpoint{
		Method: "POST",
		Data:   []DataObject{DataObject{Key: "one", Value: "#asdf#___#fdsa#___asdf___#fdsa#"}},
	}, map[string]string{"asdf": "replacement-value-for-asdf", "fdsa": "replacement-for-fdsa"})
	if err != nil {
		t.Errorf("Unexpected error: %s", err.Error())
	}
	if string(form) != "one=replacement-value-for-asdf___replacement-for-fdsa___asdf___replacement-for-fdsa" {
		t.Errorf("Data reference was not replaced")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing request client transport is modified for skipverify")
	refresh.refreshUrl = suri.String()
	refresh.refreshRequestObject(c, r, Endpoint{Method: "POST", Skipverify: true}, map[string]string{})
	if c.Transport == nil {
		t.Errorf("Client Transport was not set")
	}

	t.Log("Testing cookies are added to request if endpoint configured for it")
	r.AddCookie(&http.Cookie{Name: "one", Value: "asdf"})
	refresh.refreshUrl += "/return_cookies"
	cookies, _ := refresh.refreshRequestObject(c, r, Endpoint{Method: "POST", Cookies: true}, map[string]string{})
	if string(cookies) != "[one=asdf]" {
		t.Errorf("Cookies were not added to the endpoint")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing headers are added to request if endpoint configured for it")
	refresh.refreshUrl += "/return_headers"
	headers, _ := refresh.refreshRequestObject(c, r, Endpoint{
		Method:  "POST",
		Headers: []DataObject{DataObject{Key: "one", Value: "asdf"}, DataObject{Key: "two", Value: "fdsa"}},
	}, map[string]string{})
	if !strings.Contains(string(headers), "asdf") || !strings.Contains(string(headers), "fdsa") {
		t.Errorf("Headers were not added to the endpoint")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing header values are replaced")
	refresh.refreshUrl += "/return_headers"
	headers, _ = refresh.refreshRequestObject(c, r, Endpoint{
		Method: "POST",
		Headers: []DataObject{
			DataObject{Key: "one", Value: "#asdf#"},
			DataObject{Key: "two", Value: "#fdsa#"},
			DataObject{Key: "three", Value: "#fdsa#"},
		}}, map[string]string{"asdf": "replacement-value-for-asdf", "fdsa": "replacement-for-fdsa"})
	if !strings.Contains(string(headers), "replacement-value-for-asdf") || !strings.Contains(string(headers), "replacement-for-fdsa") || strings.Contains(string(headers), "#fdsa#") {
		t.Errorf("Headers were not added to the endpoint")
	}
	refresh.refreshUrl = uri.String()

	t.Log("Testing client.Do error will pass error down")

	t.Log("Testing resp.Body read error will pass error down")

	t.Log("Testing failure identified in response body")

	t.Log("Testing response key found in response body")
}
