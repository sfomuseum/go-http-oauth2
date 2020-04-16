package oauth2

import (
	"github.com/aaronland/go-http-crumb"
	"golang.org/x/oauth2"
)

type Options struct {
	AuthURL      string
	CookieName   string
	CookieSecret string
	CookieSalt   string
	Config       *oauth2.Config
	AuthCrumb    *crumb.CrumbConfig
	UnAuthCrumb  *crumb.CrumbConfig
}
