package flags

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/aaronland/go-http-crumb"
	"github.com/aaronland/go-string/random"
	"github.com/sfomuseum/go-flags"
	"github.com/sfomuseum/go-http-oauth2"
	goog_oauth2 "golang.org/x/oauth2"
	"strings"
	"sync"
)

var oauth2_init sync.Once

var oauth2_opts *oauth2.Options
var oauth2_err error

func AppendOAuth2Flags(fs *flag.FlagSet) error {

	fs.Bool("enable-oauth2", false, "...")

	fs.String("oauth2-client-id", "", "...")
	fs.String("oauth2-client-secret", "", "...")

	fs.String("oauth2-scopes", "", "...")

	fs.String("path-oauth2-auth", "/signin/", "...")
	fs.String("path-oauth2-token", "/auth/", "...")

	fs.String("oauth2-auth-url", "", "...")
	fs.String("oauth2-token-url", "", "...")

	fs.String("oauth2-cookie-dsn", "", "...")

	return nil
}

func OAuth2OptionsWithFlagSet(ctx context.Context, fs *flag.FlagSet) (*oauth2.Options, error) {

	oauth2_func := func() {

		client_id, err := flags.StringVar(fs, "oauth2-client-id")

		if err != nil {
			oauth2_err = err
			return
		}

		client_secret, err := flags.StringVar(fs, "oauth2-client-secret")

		if err != nil {
			oauth2_err = err
			return
		}

		auth_url, err := flags.StringVar(fs, "oauth2-auth-url")

		if err != nil {
			oauth2_err = err
			return
		}

		token_url, err := flags.StringVar(fs, "oauth2-token-url")

		if err != nil {
			oauth2_err = err
			return
		}

		str_scopes, err := flags.StringVar(fs, "oauth2-scopes")

		if err != nil {
			oauth2_err = err
			return
		}

		scopes := strings.Split(str_scopes, ",")

		path_auth, err := flags.StringVar(fs, "path-oauth2-auth")

		if err != nil {
			oauth2_err = err
			return
		}

		path_token, err := flags.StringVar(fs, "path-oauth2-token")

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

		cookie_uri, err := flags.StringVar(fs, "oauth2-cookie-uri")

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

		signin_crumb, err := NewOAuth2CrumbConfig("signin", 120)

		if err != nil {
			oauth2_err = err
			return
		}

		// not sure about this (20204016/thisisaaronland)

		signout_crumb, err := NewOAuth2CrumbConfig("signout", 3600)

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

func NewOAuth2CrumbConfig(key string, ttl int64) (*crumb.CrumbConfig, error) {

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

	separator := ":"

	cfg := &crumb.CrumbConfig{
		Extra:     extra,
		Separator: separator,
		Secret:    secret,
		TTL:       ttl,
		Key:       key,
	}

	return cfg, nil
}
