package cmd

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Mininglamp-OSS/octo-cli/internal/authstore"
	"github.com/Mininglamp-OSS/octo-cli/internal/client"
	"github.com/Mininglamp-OSS/octo-cli/internal/cmdutil"
	"github.com/Mininglamp-OSS/octo-cli/internal/config"
	"github.com/Mininglamp-OSS/octo-cli/internal/credential"
	"github.com/Mininglamp-OSS/octo-cli/internal/output"
)

func importProfile(cmd *cobra.Command, f *cmdutil.Factory, originFlag, token string) error {
	selector, err := f.ProfileSelector()
	if err != nil {
		return failErr(f, err)
	}
	store, err := f.AuthStore()
	if err != nil {
		return failErr(f, err)
	}
	var snapshot *authstore.Config
	err = store.View(cmd.Context(), func(cfg *authstore.Config) error {
		snapshot = cfg
		return nil
	})
	if err != nil {
		return failErr(f, err)
	}

	name := selector
	if name == "" {
		name = snapshot.CurrentProfile
		if name == "" {
			name = authstore.DefaultProfile
		}
	}
	previous := snapshot.Profiles[name]
	target, err := importTarget(cmd, f, &previous, originFlag)
	if err != nil {
		return failErr(f, err)
	}
	target.Verified, err = verifyImport(cmd, f, &target, token)
	if err != nil {
		return failErr(f, err)
	}
	warning, err := store.Import(cmd.Context(), name, snapshot, selector == "", &target, token)
	if err != nil {
		return failErr(f, err)
	}
	writeStoreWarning(f, warning)
	return emitJSON(f, readyProfile(name, &target))
}

func importTarget(cmd *cobra.Command, f *cmdutil.Factory, previous *authstore.Profile, originFlag string) (authstore.Profile, error) {
	cfg := f.RuntimeConfig()
	origin := cfg.APIBaseURL
	if cmd.Flags().Changed("api-base-url") {
		origin = originFlag
	} else if cfg.APIBaseURLSource == "default" && previous.APIBaseURL != "" {
		origin = previous.APIBaseURL
	}
	origin, err := config.NormalizeAPIBaseURL(origin)
	if err != nil {
		return authstore.Profile{}, output.ErrValidation(err.Error(), "use the business gateway origin")
	}
	space := cfg.SpaceID
	if space == "" {
		space = previous.SpaceID
	}
	if err := authstore.ValidateSpace(space); err != nil {
		return authstore.Profile{}, err
	}
	return authstore.Profile{APIBaseURL: origin, SpaceID: space}, nil
}

func verifyImport(cmd *cobra.Command, f *cmdutil.Factory, target *authstore.Profile, candidate string) (*authstore.Verified, error) {
	origin, path, err := currentTokenEndpoint(os.Getenv(config.EnvAuthCurrentURL))
	if err != nil {
		return nil, err
	}
	if origin != target.APIBaseURL {
		return nil, output.ErrWithHint("validation", "PROFILE_SCOPE_MISMATCH",
			"token verification origin does not match the profile API origin",
			"set "+config.EnvAuthCurrentURL+" to the self-check endpoint on the selected gateway")
	}
	httpClient := f.NewHTTPClient(&config.Config{APIBaseURL: target.APIBaseURL}, &credential.Credential{Token: candidate})
	raw, err := httpClient.Do(cmd.Context(), &client.Request{
		Method: http.MethodGet, Path: path, ExpectedStatus: http.StatusOK,
		SuppressSpaceHeader: true,
	})
	if err != nil {
		return nil, err
	}
	return verifiedImportResponse(raw, target.SpaceID)
}

func currentTokenEndpoint(raw string) (origin, path string, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.User != nil || u.ForceQuery || u.RawQuery != "" ||
		strings.Contains(raw, "#") || len(u.Path) < 2 || strings.HasPrefix(u.EscapedPath(), "//") {
		return "", "", output.ErrValidation("a full token verification URL is required", "set "+config.EnvAuthCurrentURL+" without credentials, a query, or a fragment")
	}
	origin, err = config.NormalizeAPIBaseURL((&url.URL{Scheme: u.Scheme, Host: u.Host}).String())
	if err != nil {
		return "", "", output.ErrValidation("invalid token verification origin", "set "+config.EnvAuthCurrentURL+" to an absolute HTTP(S) URL")
	}
	return origin, u.EscapedPath(), nil
}

func verifiedImportResponse(raw []byte, space string) (*authstore.Verified, error) {
	var wire struct {
		Data struct {
			Token struct {
				authstore.Verified
				Status    string `json:"status"`
				IsExpired *bool  `json:"is_expired"`
			} `json:"token"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &wire) != nil || !wire.Data.Token.Valid() ||
		wire.Data.Token.Status == "" || wire.Data.Token.IsExpired == nil {
		return nil, output.ErrAPI("INVALID_RESPONSE", "invalid TokenSelf response from the verification endpoint", "")
	}
	meta := wire.Data.Token
	if meta.Status != "active" || *meta.IsExpired {
		return nil, output.ErrAuth("token is inactive or expired", "supply an active token")
	}
	if meta.SpaceID != space {
		return nil, output.ErrWithHint("validation", "PROFILE_SCOPE_MISMATCH", "verified token belongs to a different Space", "supply a token for the target Space")
	}
	return &meta.Verified, nil
}
