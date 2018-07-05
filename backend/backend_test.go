package backend_test

import (
	"fmt"
	"testing"

	"github.com/freman/caddy-reauth/backend"
)

func TestParseOptions(t *testing.T) {
	tests := []struct {
		label   string
		options string
		expect  map[string]string
	}{{
		label:   "original options",
		options: `url=https://gitlab.example.com,skipverify=true,timeout=5s`,
		expect:  map[string]string{"url": "https://gitlab.example.com", "skipverify": "true", "timeout": "5s"},
	}, {
		label:   "ldap options",
		options: `url=ldap://ldap.example.com:389,timeout=5s,base="OU=Users,OU=Company,DC=example,DC=com",filter="(&(memberOf=CN=group,OU=Users,OU=Company,DC=example,DC=com)(objectClass=user)(sAMAccountName=%s))"`,
		expect:  map[string]string{"url": "ldap://ldap.example.com:389", "timeout": "5s", "base": "OU=Users,OU=Company,DC=example,DC=com", "filter": "(&(memberOf=CN=group,OU=Users,OU=Company,DC=example,DC=com)(objectClass=user)(sAMAccountName=%s))"},
	}, {
		label:   "absurd options",
		options: `hello=world,how="are you",not="so,bad=bar,friend",cool="yep"`,
		expect:  map[string]string{"cool": "yep", "hello": "world", "how": "are you", "not": "so,bad=bar,friend"},
	}}

	for i, test := range tests {
		t.Run(fmt.Sprintf("[%d] %s", i+1, test.label), func(t *testing.T) {

			opts, err := backend.ParseOptions(test.options)
			if err != nil {
				t.Errorf("Unexpected error %v", err)
			}

			for n, expect := range test.expect {
				if got, found := opts[n]; !found || got != expect {
					t.Errorf("expected %q, got %q", expect, got)
				}
			}
		})
	}

}
