package reauth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy"
	"github.com/freman/caddy-reauth/backend"
)

func TestCaddyReauthConfigs(t *testing.T) {
	simpleConstructor, err := backend.Lookup("simple")
	if err != nil {
		t.Fatal("Can't use simple backend: ", err)
	}
	simpleBackend, err := simpleConstructor(`username=password`)
	if err != nil {
		t.Fatal("Can't use construct backend: ", err)
	}
	testBackends := []backend.Backend{simpleBackend}

	tests := []struct {
		desc   string
		config string
		expect []Rule
		err    error
	}{
		{
			`Only take blocks, no arguments`,
			`reauth /nothing`,
			nil,
			errors.New(`Testfile:1 - Error during parsing: Wrong argument count or unexpected line ending after '/nothing'`),
		}, {
			`Make sure that at least one backend is required`,
			`reauth {
				path /test
			}`,
			nil,
			errors.New(`at least one backend required`),
		}, {
			`Make sure that path is required`,
			`reauth {
			}`,
			nil,
			errors.New(`at least one path is required`),
		}, {
			`Too many args for path`,
			`reauth {
				path /test /test2
			}`,
			nil,
			errors.New(`Testfile:2 - Error during parsing: Wrong argument count or unexpected line ending after '/test2'`),
		}, {
			`Two or more paths is ok`,
			`reauth {
				path /test
				path /test2
				simple username=password
			}`,
			[]Rule{{
				path:       []string{"/test", "/test2"},
				exceptions: nil,
				backends:   testBackends,
				onfail:     &httpBasicOnFailure{},
			}},
			nil,
		}, {
			`Insufficient args for path`,
			`reauth {
				path
			}`,
			nil,
			errors.New(`Testfile:2 - Error during parsing: Wrong argument count or unexpected line ending after 'path'`),
		}, {
			`Make sure that arg counts are checked, there should be 1 argument`,
			`reauth {
				path /test
				simple
			}`,
			nil,
			errors.New(`wrong number of arguments for simple: [] (Testfile:3)`),
		}, {
			`A perfectly valid scenario for simple`,
			`reauth {
				path /test
				simple username=password
			}`,
			[]Rule{{
				path:       []string{"/test"},
				exceptions: nil,
				backends:   testBackends,
				onfail:     &httpBasicOnFailure{},
			}},
			nil,
		}, {
			`Insufficient args for except`,
			`reauth {
				except
			}`,
			nil,
			errors.New(`Testfile:2 - Error during parsing: Wrong argument count or unexpected line ending after 'except'`),
		}, {
			`Non existant backends could be fun right?`,
			`reauth {
				path /test
				nevermakemeexistplease username=password
			}`,
			nil,
			errors.New(`unknown backend for nevermakemeexistplease (Testfile:3)`),
		}, {
			`An invalid scenario for simple`,
			`reauth {
				path /test
				simple username
			}`,
			nil,
			errors.New(`Unable to parse options string, missing pair for simple (Testfile:3)`),
		}, {
			`Single exceptions are good`,
			`reauth {
				path /test
				except /test/thing
				simple username=password
			}`,
			[]Rule{{
				path:       []string{"/test"},
				exceptions: []string{"/test/thing"},
				backends:   testBackends,
				onfail:     &httpBasicOnFailure{},
			}},
			nil,
		}, {
			`Inline multiple exceptions are not good`,
			`reauth {
				path /test
				except /test/thing /other/thing
				simple username=password
			}`,
			nil,
			errors.New(`Testfile:3 - Error during parsing: Wrong argument count or unexpected line ending after '/other/thing'`),
		}, {
			`Multiple single exceptions are good`,
			`reauth {
				path /test
				except /test/thing
				except /other/thing
				simple username=password
			}`,
			[]Rule{{
				path:       []string{"/test"},
				exceptions: []string{"/test/thing", "/other/thing"},
				backends:   testBackends,
				onfail:     &httpBasicOnFailure{},
			}},
			nil,
		}, {
			`Failure requires arguments`,
			`reauth {
				path /test
				failure
				simple username=password
			}`,
			nil,
			errors.New(`Testfile:3 - Error during parsing: Wrong argument count or unexpected line ending after 'failure'`),
		}, {
			`Status can be no arguments`,
			`reauth {
				path /test
				failure status
				simple username=password
			}`,
			[]Rule{{
				path:     []string{"/test"},
				backends: testBackends,
				onfail:   &httpStatusOnFailure{code: http.StatusUnauthorized},
			}},
			nil,
		}, {
			`Status can be one arguments`,
			`reauth {
				path /test
				failure status code=500
				simple username=password
			}`,
			[]Rule{{
				path:     []string{"/test"},
				backends: testBackends,
				onfail:   &httpStatusOnFailure{code: http.StatusInternalServerError},
			}},
			nil,
		}, {
			`Status can not be more than one arguments`,
			`reauth {
				path /test
				failure status code=500 thing
				simple username=password
			}`,
			nil,
			errors.New(`Testfile:3 - Error during parsing: Wrong argument count or unexpected line ending after 'thing'`),
		}, {
			`Redirect requires 1 argument`,
			`reauth {
				path /test
				failure redirect
				simple username=password
			}`,
			nil,
			errors.New(`Testfile:3 - Error during parsing: configuration required for failure redirect`),
		}, {
			`Redirect requires 1 argument`,
			`reauth {
				path /test
				failure redirect code=300
				simple username=password
			}`,
			nil,
			errors.New(`Testfile:3 - Error during parsing: target url required for failure redirect`),
		}, {
			`What's a foo failure?`,
			`reauth {
				path /test
				failure foo
				simple username=password
			}`,
			nil,
			errors.New(`Testfile:3 - Error during parsing: unknown failure handler foo: `),
		}, {
			`Only one failure please`,
			`reauth {
				path /test
				failure status
				failure status
				simple username=password
			}`,
			nil,
			errors.New(`Testfile:4 - Error during parsing: Wrong argument count or unexpected line ending after 'failure'`),
		},
	}

	for i, tc := range tests {
		t.Logf("Testing configuration %d (%s)", i+1, tc.desc)
		c := caddy.NewTestController("http", tc.config)
		actual, err := parseConfiguration(c)
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
			if actual != nil {
				t.Errorf("Expected nil rules, got %v", actual)
			}
		} else if !reflect.DeepEqual(tc.expect, actual) {
			t.Errorf("Expected %v got %v", tc.expect, actual)
		}
	}
}
