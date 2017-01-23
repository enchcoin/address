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


# Contribution
Improvements to the codebase and pull requests are encouraged.


