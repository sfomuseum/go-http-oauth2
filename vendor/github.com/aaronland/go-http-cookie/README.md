# go-http-cookie

Go package for working with HTTP cookies.

## Documentation

[![Go Reference](https://pkg.go.dev/badge/github.com/aaronland/go-http-cookie.svg)](https://pkg.go.dev/github.com/aaronland/go-http-cookie)

## Example

_Error handling omitted for the sake of brevity._

```
package main

import (
	"fmt"
	"github.com/aaronland/go-http-cookie"	
)

func main() {

	name := "c"
	secret := "s33kret"
	salt := "s4lty"
	
	cookie_uri := fmt.Sprintf("encrypted://?name=%s&secret=%s&salt=%s", name, secret, salt)
	ck, _ := cookie.NewCookie(ctx, cookie_uri)
}
```

## See also

* https://github.com/aaronland/go-secretbox
* https://godoc.org/golang.org/x/crypto/nacl/secretbox
* https://github.com/awnumar/memguard