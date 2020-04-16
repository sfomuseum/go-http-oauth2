package oauth2

import (
	"github.com/aaronland/go-http-crumb"
	"golang.org/x/oauth2"
)

type Options struct {
	SigninURL    string
	CookieName   string
	CookieSecret string
	CookieSalt   string
	Config       *oauth2.Config
	SigninCrumb  *crumb.CrumbConfig
	SignoutCrumb *crumb.CrumbConfig
}
