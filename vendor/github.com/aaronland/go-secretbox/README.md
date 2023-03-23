# go-secretbox

A thin wrapper around the Golang [secretbox](https://godoc.org/golang.org/x/crypto/nacl/secretbox) and [awnumar/memguard](https://github.com/awnumar/memguard) package.

## Documentation

[![Go Reference](https://pkg.go.dev/badge/github.com/aaronland/go-secretbox.svg)](https://pkg.go.dev/github.com/aaronland/go-secretbox)

## Example

```
package main

import (
	"github.com/aaronland/go-secretbox"
	"github.com/awnumar/memguard"	
	"log"
)

func main() {

	secret := "s33kret"
	salt := "s4lty"
	plain := "hello world"

	secret_buf := memguard.NewBufferFromBytes([]byte(secret))
	defer secret_buf.Destroy()
	
	opts := secretbox.NewSecretboxOptions()
	opts.Salt = salt

	sb, _ := secretbox.NewSecretboxWithBuffer(secret_buf, opts)

	locked, _ := sb.Lock([]byte(plain))
	unlocked, _ := sb.Unlock(locked)

	if string(unlocked.String()) != plain {
		log.Fatal("Unlock failed")
	}
}
```

_Error handling omitted for the sake of brevity._

## See also

* https://godoc.org/golang.org/x/crypto/nacl/secretbox
* https://github.com/awnumar/memguard