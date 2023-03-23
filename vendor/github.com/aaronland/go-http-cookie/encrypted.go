package cookie

import (
	"context"
	"fmt"
	"github.com/aaronland/go-secretbox"
	"github.com/aaronland/go-string/random"
	"github.com/awnumar/memguard"
	"net/http"
	"net/url"
)

func init() {
	ctx := context.Background()
	RegisterCookie(ctx, "encrypted", NewEncryptedCookie)
	memguard.CatchInterrupt()
}

// EncryptedCookie implements the `Cookie` interface for working with cookies whose values have been encrypted.
type EncryptedCookie struct {
	Cookie
	name   string
	secret *memguard.Enclave
	salt   string
}

// NewRandomEncryptedCookieSecret returns a random salt value suitable for `encrypted://` cookie URIs.
func NewRandomEncryptedCookieSecret() (string, error) {

	r_opts := random.DefaultOptions()
	r_opts.AlphaNumeric = true

	secret, err := random.String(r_opts)

	if err != nil {
		return "", fmt.Errorf("Failed to generate secret, %w", err)
	}

	return secret, nil
}

// NewRandomEncryptedCookieSalt returns a random salt value suitable for `encrypted://` cookie URIs.
func NewRandomEncryptedCookieSalt() (string, error) {

	r_opts := random.DefaultOptions()
	r_opts.AlphaNumeric = true

	salt, err := random.String(r_opts)

	if err != nil {
		return "", fmt.Errorf("Failed to generate salt, %w", err)
	}

	return salt, nil
}

// NewRandomEncryptedCookieURI() returns a new URI for creating an `EncryptedCookie` instance for 'name' with random values for the required secret and salt.
func NewRandomEncryptedCookieURI(name string) (string, error) {

	secret, err := NewRandomEncryptedCookieSecret()

	if err != nil {
		return "", fmt.Errorf("Failed to generate secret, %w", err)
	}

	salt, err := NewRandomEncryptedCookieSalt()

	if err != nil {
		return "", fmt.Errorf("Failed to generate salyt, %w", err)
	}

	cookie_uri := fmt.Sprintf("encrypted://?name=%s&secret=%s&salt=%s", name, secret, salt)
	return cookie_uri, nil
}

// NewEncryptedCookie() returns a new `EncryptedCookie` instance derived from 'uri' which is expected to take the form of:
//
// 	encrypted://?name={NAME}&secret={SECRET}&salt={SECRET}
//
// Where `{NAME}` is the name of the cookie for all subsequent operations; `{SECRET}` is the secret key used to encrypt the value of the cookie; `{SALT}` is the salt used to encrypt the cookie.
func NewEncryptedCookie(ctx context.Context, uri string) (Cookie, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, fmt.Errorf("Failed to parse URL, %w", err)
	}

	q := u.Query()

	name := q.Get("name")
	secret := q.Get("secret")
	salt := q.Get("salt")

	if name == "" {
		return nil, fmt.Errorf("Invalid name value (empty)")
	}

	if secret == "" {
		return nil, fmt.Errorf("Invalid secret value (empty)")
	}

	if salt == "" {
		return nil, fmt.Errorf("Invalid salt value (empty)")
	}

	secret_key := memguard.NewEnclave([]byte(secret))

	c := EncryptedCookie{
		name:   name,
		secret: secret_key,
		salt:   salt,
	}

	return &c, nil
}

// GetString returns the value of the cookie associated with 'c' in 'req' as an unencrypted string.
func (c *EncryptedCookie) GetString(req *http.Request) (string, error) {

	buf, err := c.Get(req)

	if err != nil {
		return "", fmt.Errorf("Failed to get cookie, %w", err)
	}

	defer buf.Destroy()

	return buf.String(), nil
}

// GetString returns the value of the cookie associated with 'c' in 'req' as an unencrypted `memguard.LockedBuffer` instance.
func (c *EncryptedCookie) Get(req *http.Request) (*memguard.LockedBuffer, error) {

	http_cookie, err := req.Cookie(c.name)

	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve cookie, %w", err)
	}

	opts := secretbox.NewSecretboxOptions()
	opts.Salt = c.salt

	sb, err := secretbox.NewSecretboxWithEnclave(c.secret, opts)

	if err != nil {
		return nil, fmt.Errorf("Failed to create secretbox, %w", err)
	}

	return sb.Unlock(http_cookie.Value)
}

// SetString assigns 'value' as an encrypted string to a cookie associated with 'c' to 'rsp'.
func (c *EncryptedCookie) SetString(rsp http.ResponseWriter, value string) error {

	buf := memguard.NewBufferFromBytes([]byte(value))
	defer buf.Destroy()

	return c.Set(rsp, buf)
}

// Set assigns 'buf' as an encrypted string to a cookie associated with 'c' to 'rsp'.
func (c *EncryptedCookie) Set(rsp http.ResponseWriter, buf *memguard.LockedBuffer) error {

	http_cookie := &http.Cookie{}
	return c.SetWithCookie(rsp, buf, http_cookie)
}

// SetStringWithCookie assigns 'value' as an encrypted string to 'http_cookie' which is assigned to 'rsp'.
func (c *EncryptedCookie) SetStringWithCookie(rsp http.ResponseWriter, value string, http_cookie *http.Cookie) error {

	buf := memguard.NewBufferFromBytes([]byte(value))
	defer buf.Destroy()

	return c.SetWithCookie(rsp, buf, http_cookie)
}

// SetWithCookie assigns 'buf' as an encrypted string to 'http_cookie' which is assigned to 'rsp'.
func (c *EncryptedCookie) SetWithCookie(rsp http.ResponseWriter, buf *memguard.LockedBuffer, http_cookie *http.Cookie) error {

	if http_cookie.Name != "" {
		return fmt.Errorf("Cookie name already set")
	}

	opts := secretbox.NewSecretboxOptions()
	opts.Salt = c.salt

	sb, err := secretbox.NewSecretboxWithEnclave(c.secret, opts)

	if err != nil {
		return fmt.Errorf("Failed to create new secretbox, %w", err)
	}

	enc, err := sb.LockWithBuffer(buf)

	if err != nil {
		return fmt.Errorf("Failed to lock buffer, %w", err)
	}

	http_cookie.Name = c.name
	http_cookie.Value = enc

	http.SetCookie(rsp, http_cookie)
	return nil
}

// Delete removes the cookie associated with 'c' from 'rsp'.
func (c *EncryptedCookie) Delete(rsp http.ResponseWriter) error {

	http_cookie := http.Cookie{
		Name:   c.name,
		Value:  "",
		MaxAge: -1,
	}

	http.SetCookie(rsp, &http_cookie)
	return nil
}
