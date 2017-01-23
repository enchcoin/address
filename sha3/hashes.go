// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// This file provides functions for creating instances of the SHA-3
// and SHAKE hash functions, as well as utility functions for hashing
// bytes.

import (
	"hash"
)

// NewKeccak512 creates a new Keccak-512 hash.
func NewKeccak512() hash.Hash { return &state{rate: 72, outputLen: 64, dsbyte: 0x01} }

// NewKeccak256 creates a new Keccak-256 hash.
func NewKeccak256() hash.Hash { return &state{rate: 136, outputLen: 32, dsbyte: 0x01} }

// KeccakSum256 writes an arbitrary-length digest of data into hash.
func KeccakSum256(data []byte) (digest [32]byte) {
	h := NewKeccak256()
	h.Write(data)
	h.Sum(digest[:0])
	return
}

// KeccakSum512 writes an arbitrary-length digest of data into hash.
func KeccakSum512(data []byte) (digest [64]byte) {
	h := NewKeccak512()
	h.Write(data)
	h.Sum(digest[:0])
	return
}
