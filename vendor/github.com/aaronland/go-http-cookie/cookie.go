package cookie

import (
	"context"
	"fmt"
	"github.com/aaronland/go-roster"
	"github.com/awnumar/memguard"
	"net/http"
	"net/url"
	"sort"
)

// Cookie is an interface for working with HTTP cookies.
type Cookie interface {
	// Get() returns the value of a HTTP cookie as a `awnumar/memguard.LockedBuffer` instance.
	Get(*http.Request) (*memguard.LockedBuffer, error)
	// GetString() returns the value of a HTTP cookie as a string.
	GetString(*http.Request) (string, error)
	// Get() assigned the value of a HTTP cookie from a `awnumar/memguard.LockedBuffer` instance.
	Set(http.ResponseWriter, *memguard.LockedBuffer) error
	// Get() assigned the value of a HTTP cookie from a string.
	SetString(http.ResponseWriter, string) error
	// SetWithCookie() assigned the value of a specific HTTP cookie from a `awnumar/memguard.LockedBuffer` instance.
	SetWithCookie(http.ResponseWriter, *memguard.LockedBuffer, *http.Cookie) error
	// SetStringWithCookie() assigned the value of a specific HTTP cookie from a string.
	SetStringWithCookie(http.ResponseWriter, string, *http.Cookie) error
	// Delete() removes the cookie from an HTTP response.
	Delete(http.ResponseWriter) error
}

// CookieInitializeFunc is a function used to initialize an implementation of the `Cookie` interface.
type CookieInitializeFunc func(context.Context, string) (Cookie, error)

var cookies roster.Roster

func ensureCookies() error {

	if cookies == nil {

		r, err := roster.NewDefaultRoster()

		if err != nil {
			return err
		}

		cookies = r
	}

	return nil
}

// RegisterCookie() associates 'scheme' with 'f' in an internal list of avilable `Cookie` implementations.
func RegisterCookie(ctx context.Context, scheme string, f CookieInitializeFunc) error {

	err := ensureCookies()

	if err != nil {
		return err
	}

	return cookies.Register(ctx, scheme, f)
}

// NewCookie() returns a new instance of `Cookie` for the scheme associated with 'uri'. It is assumed that this scheme
// will have previously been "registered" with the `RegisterCookie` method.
func NewCookie(ctx context.Context, uri string) (Cookie, error) {

	err := ensureCookies()

	if err != nil {
		return nil, err
	}

	u, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	scheme := u.Scheme

	i, err := cookies.Driver(ctx, scheme)

	if err != nil {
		return nil, err
	}

	f := i.(CookieInitializeFunc)
	return f(ctx, uri)
}

// Schemes() returns the list of schemes that have been "registered".
func Schemes() []string {
	ctx := context.Background()
	drivers := cookies.Drivers(ctx)

	schemes := make([]string, len(drivers))

	for idx, dr := range drivers {
		schemes[idx] = fmt.Sprintf("%s://", dr)
	}

	sort.Strings(schemes)
	return schemes
}
