package cmd

import (
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-cli/internal/client"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
)

func TestAPIPreviewRedactsDeclaredSecrets(t *testing.T) {
	const key = "fixture-key-12345"
	const password = "fixture-password-67890"
	for _, mount := range []string{"/v1", "/v2"} {
		t.Run(mount, func(t *testing.T) {
			f := newTestFactoryWithReg()
			cfg := &config.Config{APIBaseURL: "https://example.invalid", Token: "app_fixture", Format: "json"}
			cred := &credential.Credential{Token: cfg.Token}
			f.SetConfig(cfg)
			f.SetCredential(cred)
			f.SetClient(client.New(cfg, cred, client.Options{DryRun: true}))

			out, _, err := execRoot(t, f, "api", "POST", mount+"/keys/"+key+"/verify",
				"--dry-run", "--data", `{"password":"`+password+`"}`)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out, key) || strings.Contains(out, password) {
				t.Fatal("request preview exposes a declared secret")
			}
			if !strings.Contains(out, mount+"/keys/") || strings.Count(out, "***REDACTED***") != 2 {
				t.Fatalf("expected the resolved route and both redactions: %s", out)
			}
		})
	}
}

func TestMatchPathTemplate_UnreservedLiteralEscapes(t *testing.T) {
	const rawID = "opaque%2Fid%7E"
	for _, tc := range []struct {
		name, template, path string
		match                bool
	}{
		{"unreserved characters", "/aZ0-._~/{id}", "/%61%5A%30%2D%2e%5f%7E/" + rawID, true},
		{"escaped template literal", "/%61%5A%30%2D%2e%5f%7E/{id}", "/aZ0-._~/" + rawID, true},
		{"literal case remains significant", "/A/{id}", "/%61/" + rawID, false},
		{"encoded slash stays within its segment", "/plugins/install/{id}", "/plugins%2Finstall/" + rawID, false},
		{"double encoding stays encoded", "/plugins/install/{id}", "/plugins%252Finstall/" + rawID, false},
		{"reserved characters stay encoded", "/market+api/{id}", "/market%2Bapi/" + rawID, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values, matched := matchPathTemplate(tc.template, pathSegments(tc.path))
			if matched != tc.match {
				t.Fatalf("match = %v, want %v for %q against %q", matched, tc.match, tc.path, tc.template)
			}
			if matched && values["id"] != rawID {
				t.Errorf("captured id = %q, want unchanged %q", values["id"], rawID)
			}
		})
	}
}

// TestAPI_ParamsArrayElementsAreJSONNotGoSyntax is round-16 P2-3.
//
// The array arm of parseParamsJSON fell through to fmt.Sprintf("%v", item) for anything that
// was not a json.Number, so an object became `map[id:9007199254740993]`, a nested array
// `[1 2]`, and null `<nil>` — Go's own debug spelling on the wire. The *same* value at top
// level is marshalled correctly by the default arm, so the two arms disagreed about what a
// non-scalar query value is, and the previous round edited this exact switch while fixing
// only its numeric half.
func TestAPI_ParamsArrayElementsAreJSONNotGoSyntax(t *testing.T) {
	const big = "9007199254740993" // 2^53 + 1

	q, err := parseParamsJSON(`{"filters":[{"id":` + big + `}],"nest":[[1,2]],"vals":[null],` +
		`"mixed":["s",1,true],"top":{"id":` + big + `}}`)
	if err != nil {
		t.Fatalf("parseParamsJSON: %v", err)
	}
	for key, want := range map[string][]string{
		"filters": {`{"id":` + big + `}`},
		"nest":    {`[1,2]`},
		"vals":    {`null`},
		"mixed":   {"s", "1", "true"},
		"top":     {`{"id":` + big + `}`},
	} {
		got := q[key]
		if len(got) != len(want) {
			t.Errorf("%s = %v, want %v", key, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s[%d] = %q, want %q", key, i, got[i], want[i])
			}
		}
	}
}
