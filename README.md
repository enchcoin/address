[![Build Status](https://travis-ci.org/gonem/address.svg?branch=master)](https://travis-ci.org/gonem/address)
[![GoDoc](https://godoc.org/github.com/gonem/address?status.svg)](https://godoc.org/github.com/gonem/address)
[![GitHub license](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/gonem/address/LICENSE)


# address 

## Overview

This  library is for handling NEM address, including generate private keys, sign/vefiry and serializing.

## Requirements

This requires

* git
* go 1.3+


## Installation

     $ go get github.com/gonem/address


## Example
(This example omits error handlings for simplicity.)

```go

import "github.com/gonem/address"

func main(){
	key, err := address.Generate(address.MainNet)
	adr := key.PublicKey().Address()
	data := []byte("test data")
	sig, err := key.Sign(data)
	err = key.PublicKey().Verify(sig, data)
	..
}
```

## Note

In [NEM Technical Reference](https://www.nem.io/NEM_techRef.pdf):
```
3    Cryptography

For the hash function H mentioned in the paper,  NEM uses the 512 bit SHA3 hash
function.
```

But in fact, H is Keccak-512, not SHA3-512. And Golang doens't have
Keccak-512 as default and in golang.org/x/crypto. It annoyed me too much :anger:

# Contribution
Improvements to the codebase and pull requests are encouraged.


