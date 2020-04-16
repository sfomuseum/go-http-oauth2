package flags

import (
	"flag"
)

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
