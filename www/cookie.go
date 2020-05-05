package www

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aaronland/go-http-cookie"
	"github.com/aaronland/go-http-sanitize"
	"github.com/sfomuseum/go-http-oauth2"
	"github.com/awnumar/memguard"
	goog_oauth2 "golang.org/x/oauth2"
	_ "log"
	"net/http"
	"net/url"
)

const CONTEXT_TOKEN_KEY string = "token"

func EnsureOAuth2TokenCookieHandlerWithErrorHandler(opts *oauth2.Options, next http.Handler, error_handler http.Handler) http.Handler {
	return next // not implemented
}

func EnsureOAuth2TokenCookieHandler(opts *oauth2.Options, next http.Handler) http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		token, err := GetOAuth2TokenFromCookie(opts, req)

		if err != nil && err != http.ErrNoCookie {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		if err != nil {
			http.Redirect(rsp, req, opts.AuthURL, 303)
			return
		}

		req, err = SetOAuth2TokenContext(req, token)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		next.ServeHTTP(rsp, req)
	}

	h := http.HandlerFunc(fn)
	return h
}

func OAuth2TokenCookieAuthorizeHandlerWithErrorHandler(opts *oauth2.Options, error_handler http.Handler) (http.Handler, error) {
	return nil, errors.New("Not implemented")
}

func OAuth2TokenCookieAuthorizeHandler(opts *oauth2.Options) (http.Handler, error) {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		cfg := opts.Config

		token, err := GetOAuth2TokenFromCookie(opts, req)

		if err != nil && err != http.ErrNoCookie {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		if token != nil {
			http.Redirect(rsp, req, "/", 303)
			return
		}

		scheme := "http"

		// because this: https://github.com/golang/go/issues/28940#issuecomment-441749380

		if req.TLS != nil {
			scheme = "https"
		}

		redir := url.URL{}
		redir.Scheme = scheme
		redir.Host = req.Host
		redir.Path = cfg.RedirectURL

		redir_url := redir.String()
		cfg.RedirectURL = redir_url

		state, err := opts.AuthCrumb.Generate(req)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		auth_url := cfg.AuthCodeURL(state, goog_oauth2.AccessTypeOnline)

		http.Redirect(rsp, req, auth_url, http.StatusSeeOther)
		return
	}

	h := http.HandlerFunc(fn)
	return h, nil
}

func OAuth2AccessTokenCookieHandlerWithErrorHandler(opts *oauth2.Options, error_handler http.Handler) (http.Handler, error) {
	return nil, errors.New("Not implemented")
}

func OAuth2AccessTokenCookieHandler(opts *oauth2.Options) (http.Handler, error) {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		cfg := opts.Config

		code, err := sanitize.RequestString(req, "code")

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusBadRequest)
			return
		}

		if code == "" {
			http.Error(rsp, "Missing code", http.StatusBadRequest)
			return
		}

		state, err := sanitize.RequestString(req, "state")

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusBadRequest)
			return
		}

		if state == "" {
			http.Error(rsp, "Missing state", http.StatusBadRequest)
			return
		}

		ok, err := opts.AuthCrumb.Validate(req, state)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		if !ok {
			http.Error(rsp, err.Error(), http.StatusBadRequest)
			return
		}

		ctx := req.Context()

		tok, err := cfg.Exchange(ctx, code, goog_oauth2.AccessTypeOnline)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusBadRequest)
			return
		}

		ck, err := NewOAuth2TokenCookie(ctx, opts)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		enc_token, err := json.Marshal(tok)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		buf_token := memguard.NewBufferFromBytes(enc_token)

		// https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00#section-4.1.1

		http_cookie := &http.Cookie{
			SameSite: http.SameSiteLaxMode,
			// SameSite: http.SameSiteStrictMode,	// I can not make this work... (20200416/thisisaaronland)
			Expires: tok.Expiry,
			Path:    "/",
		}

		// because this: https://github.com/golang/go/issues/28940#issuecomment-441749380

		if req.TLS != nil {
			http_cookie.Secure = true
		}

		err = ck.SetWithCookie(rsp, buf_token, http_cookie)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		// get internal redirect URL here... (see above)

		redir_url := "/"

		http.Redirect(rsp, req, redir_url, 303)
		return
	}

	h := http.HandlerFunc(fn)
	return h, nil
}

// this is not ready for use yet - I still need to think through how/where
// the signout crumb is set in actual HTML pages(20200416/thisisaaronland)

func OAuth2RemoveAccessTokenCookieHandler(opts *oauth2.Options) (http.Handler, error) {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		token, err := GetOAuth2TokenFromCookie(opts, req)

		if err != nil && err != http.ErrNoCookie {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		if token != nil {

			crumb_var, err := sanitize.GetString(req, "crumb")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			ok, err := opts.UnAuthCrumb.Validate(req, crumb_var)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			if !ok {
				http.Error(rsp, err.Error(), http.StatusBadRequest)
				return
			}

			ctx := req.Context()

			ck, err := NewOAuth2TokenCookie(ctx, opts)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			err = ck.Delete(rsp)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		// this will cause an infinite loop because / is currently configured
		// as the editor page (20200416/thisisaaronland)

		http.Redirect(rsp, req, "/", 303)
		return
	}

	h := http.HandlerFunc(fn)
	return h, nil
}

func GetOAuth2TokenFromCookie(opts *oauth2.Options, req *http.Request) (*goog_oauth2.Token, error) {

	ctx := req.Context()
	ck, err := NewOAuth2TokenCookie(ctx, opts)

	if err != nil {
		return nil, err
	}

	buf_token, err := ck.Get(req)

	if err != nil && err != http.ErrNoCookie {
		return nil, err
	}

	if buf_token == nil {
		return nil, http.ErrNoCookie
	}

	var token *goog_oauth2.Token

	err = json.Unmarshal(buf_token.Bytes(), &token)

	if err != nil {
		return nil, err
	}

	return token, nil
}

func NewOAuth2TokenCookie(ctx context.Context, opts *oauth2.Options) (cookie.Cookie, error) {
	return cookie.NewCookie(ctx, opts.CookieURI)
}

func SetOAuth2TokenContext(req *http.Request, token *goog_oauth2.Token) (*http.Request, error) {

	ctx := req.Context()
	ctx = context.WithValue(ctx, CONTEXT_TOKEN_KEY, token)

	return req.WithContext(ctx), nil
}

func GetOAuth2TokenContext(req *http.Request) (*goog_oauth2.Token, error) {

	ctx := req.Context()
	v := ctx.Value(CONTEXT_TOKEN_KEY)

	if v == nil {
		return nil, nil
	}

	token := v.(*goog_oauth2.Token)
	return token, nil
}
