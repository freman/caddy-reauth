package simple

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestAuthenticate(t *testing.T) {
	auth := &Simple{credentials: map[string]string{"bob-bcrypt": "secret"}}

	t.Log("Testing no credentials")
	r, _ := http.NewRequest("GET", "https://test.example.com", nil)
	ok, err := auth.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing wrong credentials")
	r.SetBasicAuth("fred", "blogs")
	ok, err = auth.Authenticate(r)
	if err != nil {
		t.Errorf("Unexpected error `%v`", err)
	}
	if ok {
		t.Error("Authenticate should have failed")
	}

	t.Log("Testing correct credentials")
	r.SetBasicAuth("bob-bcrypt", "secret")
	ok, err = auth.Authenticate(r)
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
		expect *Simple
		err    error
	}{
		{
			`Empty configuration`,
			``,
			nil,
			errors.New(`Unable to parse options string, missing pair`),
		}, {
			`Test correct usage`,
			`username=password`,
			&Simple{credentials: map[string]string{"username": "password"}},
			nil,
		}, {
			`Test multiple users`,
			`username=password,bob=bcrypt`,
			&Simple{credentials: map[string]string{"username": "password", "bob": "bcrypt"}},
			nil,
		}, {
			`Test bad configuration`,
			`username`,
			nil,
			errors.New(`Unable to parse options string, missing pair`),
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
			actual, ok := be.(*Simple)
			if !ok {
				t.Errorf("Expected *Simple, got %T", be)
			} else if !reflect.DeepEqual(tc.expect, actual) {
				t.Errorf("Expected %#v got %#v", tc.expect, actual)
			}
		}
	}
}
