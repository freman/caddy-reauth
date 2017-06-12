package reauth

import (
	"testing"

	"github.com/mholt/caddy"
)

func TestCaddyReauthConfig(t *testing.T) {
	test := `reauth {
		path /test
		upstream http://google.com
	}`

	c := caddy.NewTestController("http", test)
	actual, err := parse(c)
	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	if l := len(actual); l != 1 {
		t.Errorf("Didn't get one rule, got %d", l)
	}

	if actual[0].Path != "/test" {
		t.Errorf("Expected path: /test got path: %s", actual[0].Path)
	}

	if actual[0].Upstream.String() != "http://google.com" {
		t.Errorf("Expected path: /test got path: %s", actual[0].Upstream.String())
	}
}
