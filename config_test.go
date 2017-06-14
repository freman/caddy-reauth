package reauth

import (
	"errors"
	"reflect"
	"testing"

	"github.com/freman/caddy-reauth/backend"
	"github.com/mholt/caddy"
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
			errors.New(`Testfile:1 - Parse error: Wrong argument count or unexpected line ending after '/nothing'`),
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
			errors.New(`path is a required parameter`),
		}, {
			`Too many args for path`,
			`reauth {
				path /test /test2
			}`,
			nil,
			errors.New(`Testfile:2 - Parse error: Wrong argument count or unexpected line ending after '/test2'`),
		}, {
			`Too many copies of path`,
			`reauth {
				path /test
				path /test
			}`,
			nil,
			errors.New(`Testfile:3 - Parse error: Wrong argument count or unexpected line ending after '/test'`),
		}, {
			`Insufficient args for path`,
			`reauth {
				path 
			}`,
			nil,
			errors.New(`Testfile:2 - Parse error: Wrong argument count or unexpected line ending after 'path'`),
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
				path:       "/test",
				exceptions: nil,
				backends:   testBackends,
			}},
			nil,
		}, {
			`Insufficient args for except`,
			`reauth {
				except 
			}`,
			nil,
			errors.New(`Testfile:2 - Parse error: Wrong argument count or unexpected line ending after 'except'`),
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
			errors.New(`backend configuration has to be in form 'key1=value1,key2=..', but was username for simple (Testfile:3)`),
		}, {
			`Single exceptions are good`,
			`reauth {
				path /test
				except /test/thing
				simple username=password
			}`,
			[]Rule{{
				path:       "/test",
				exceptions: []string{"/test/thing"},
				backends:   testBackends,
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
			errors.New(`Testfile:3 - Parse error: Wrong argument count or unexpected line ending after '/other/thing'`),
		}, {
			`Multiple single exceptions are good`,
			`reauth {
				path /test
				except /test/thing
				except /other/thing
				simple username=password
			}`,
			[]Rule{{
				path:       "/test",
				exceptions: []string{"/test/thing", "/other/thing"},
				backends:   testBackends,
			}},
			nil,
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
