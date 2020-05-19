package flags

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/aaronland/go-http-crumb"
	"github.com/aaronland/go-string/random"
	"github.com/sfomuseum/go-flags/lookup"
	"github.com/sfomuseum/go-http-oauth2"
	goog_oauth2 "golang.org/x/oauth2"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

var oauth2_init sync.Once

var oauth2_opts *oauth2.Options
var oauth2_err error

func AppendOAuth2Flags(fs *flag.FlagSet) error {

	fs.Bool("enable-oauth2", false, "Enable support for logging in through an OAuth2 provider.")

	fs.String("oauth2-client-id", "", "The OAuth2 application client ID used for validating users.")
	fs.String("oauth2-client-secret", "", "The OAuth2 application secret used for validating users.")

	fs.String("oauth2-scopes", "", "A comma-separated list of OAuth2 scopes to request when validating users.")

	fs.String("path-oauth2-auth", "/signin/", "The relative path where users log in to this application.")
	fs.String("path-oauth2-token", "/auth/", "The relative path users are redirected after being validated by an OAuth2 provider.")

	fs.String("oauth2-auth-url", "", "The URL of the OAuth2 provider's authorization endpoint.")
	fs.String("oauth2-token-url", "", "The URL of the OAuth2 provider's token retrieval endpoint.")

	fs.String("oauth2-cookie-uri", "", "A valid aaronland/go-http-cookie.Cookie URI string.")

	return nil
}

func OAuth2OptionsWithFlagSet(ctx context.Context, fs *flag.FlagSet) (*oauth2.Options, error) {

	oauth2_func := func() {

		client_id, err := lookup.StringVar(fs, "oauth2-client-id")

		if err != nil {
			oauth2_err = err
			return
		}

		client_secret, err := lookup.StringVar(fs, "oauth2-client-secret")

		if err != nil {
			oauth2_err = err
			return
		}

		auth_url, err := lookup.StringVar(fs, "oauth2-auth-url")

		if err != nil {
			oauth2_err = err
			return
		}

		token_url, err := lookup.StringVar(fs, "oauth2-token-url")

		if err != nil {
			oauth2_err = err
			return
		}

		str_scopes, err := lookup.StringVar(fs, "oauth2-scopes")

		if err != nil {
			oauth2_err = err
			return
		}

		scopes := strings.Split(str_scopes, ",")

		path_auth, err := lookup.StringVar(fs, "path-oauth2-auth")

		if err != nil {
			oauth2_err = err
			return
		}

		path_token, err := lookup.StringVar(fs, "path-oauth2-token")

		if err != nil {
			oauth2_err = err
			return
		}

		oauth2_cfg := &goog_oauth2.Config{
			ClientID:     client_id,
			ClientSecret: client_secret,
			Scopes:       scopes,
			Endpoint: goog_oauth2.Endpoint{
				AuthURL:  auth_url,
				TokenURL: token_url,
			},
			RedirectURL: path_token,
		}

		cookie_uri, err := lookup.StringVar(fs, "oauth2-cookie-uri")

		if err != nil {
			oauth2_err = err
			return
		}

		if cookie_uri == "debug" {

			r_opts := random.DefaultOptions()
			r_opts.AlphaNumeric = true

			name := "t"

			secret, err := random.String(r_opts)

			if err != nil {
				oauth2_err = err
				return
			}

			salt, err := random.String(r_opts)

			if err != nil {
				oauth2_err = err
				return
			}

			cookie_uri = fmt.Sprintf("encrypted://?name=%s&secret=%s&salt=%s", name, secret, salt)
		}

		signin_crumb, err := NewOAuth2Crumb(ctx, "signin", 120)

		if err != nil {
			oauth2_err = err
			return
		}

		signout_crumb, err := NewOAuth2Crumb(ctx, "signout", 3600)

		if err != nil {
			oauth2_err = err
			return
		}

		oauth2_opts = &oauth2.Options{
			Config:      oauth2_cfg,
			CookieURI:   cookie_uri,
			AuthCrumb:   signin_crumb,
			UnAuthCrumb: signout_crumb,
			AuthURL:     path_auth,
		}
	}

	oauth2_init.Do(oauth2_func)

	if oauth2_err != nil {
		return nil, oauth2_err
	}

	if oauth2_opts == nil {
		return nil, errors.New("Failed to construct OAuth2 options")
	}

	return oauth2_opts, nil
}

func NewOAuth2Crumb(ctx context.Context, key string, ttl int64) (crumb.Crumb, error) {

	r_opts := random.DefaultOptions()
	r_opts.AlphaNumeric = true

	secret, err := random.String(r_opts)

	if err != nil {
		return nil, err
	}

	r_opts.Length = 8
	extra, err := random.String(r_opts)

	if err != nil {
		return nil, err
	}

	str_ttl := strconv.FormatInt(ttl, 10)

	params := url.Values{}
	params.Set("extra", extra)
	params.Set("separator", ":")
	params.Set("secret", secret)
	params.Set("ttl", str_ttl)
	params.Set("key", key)

	crumb_uri := fmt.Sprintf("encrypted://?%s", params.Encode())

	return crumb.NewCrumb(ctx, crumb_uri)
}
