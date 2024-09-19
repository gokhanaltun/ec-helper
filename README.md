# ec-helper

---

The **ec-helper** Go package is designed to simplify the management of both `ECDSA` and `ECDH` operations. This package requires only the generation of an ECDSA key and provides key management that can be used for both `ECDSA` and `ECDH` operations. Additionally, it supports converting these keys to `PEM` format and loading keys from `PEM` format.

---

## Installation

To install the package, use the following command:

```bash
go get github.com/gokhanaltun/ec-helper
```

## Usage

### `ECDSA` Key Generation and `EcKey` Object Creation

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    echelper "github.com/gokhanaltun/ec-helper"
)

func main() {
    // create a new ECDSA key
    privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        // handle error
    }

    // create a new EcKey object
    ecKey, err := echelper.NewEcKey(privKey)
    if err != nil {
        // handle error
    }
}
```

### Converting a `Private Key` to `PEM` Format

```go
pemData, err := ecKey.PrivToPem()
if err != nil {
    // handle error
}
```

### Loading a `EcKey` from `PEM` Format

```go
ecKey, err := echelper.FromPrivPem(pemData)
if err != nil {
    // handle error
}
```

### Converting a `Public Key` to `PEM` Format

```go
pemData, err := ecKey.PubToPem()
if err != nil {
    // handle error
}
```

### Loading a `Public Key` from `PEM` Format

```go
ecdsaPublicKey, err := ecKey.PubFromPem(pemData)
if err != nil {
    // handle error
}
```

## End:
You can perform other ECDSA and ECDH operations using `ecKey.EcdsaPrivKey` and `ecKey.EcdhPrivKey`.
