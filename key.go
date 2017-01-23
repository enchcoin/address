/*
 * Copyright (c) 2016, Shinya Yagyu
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package address

import (
	"encoding/base32"

	"golang.org/x/crypto/ripemd160"

	"github.com/gonem/address/ed25519"
	"github.com/gonem/address/sha3"
)

//Address Headers
var (
	//MainNet is params for main net.
	MainNet byte = 0x68
	//TestNet is params for test net.
	TestNet byte = 0x98
)

//PublicKey represents public key for NEM
type PublicKey struct {
	ed25519.PublicKey
	param byte
}

//PrivateKey represents private key for NEM
type PrivateKey struct {
	ed25519.PrivateKey
	param byte
}

//NewPublicKey returns PublicKey struct using public key hex string.
func NewPublicKey(pubKeyByte []byte, param byte) *PublicKey {
	return &PublicKey{
		PublicKey: ed25519.PublicKey(pubKeyByte),
		param:     param,
	}
}

//NewPrivateKey creates and returns PrivateKey from bytes.
func NewPrivateKey(priv []byte, param byte) (*PrivateKey, error) {
	privatek, err := ed25519.NewKey(priv)
	return &PrivateKey{
		PrivateKey: privatek,
		param:      param,
	}, err
}

//Generate generates random PublicKey and PrivateKey.
func Generate(param byte) (*PrivateKey, error) {
	priv, err := ed25519.GenerateKey(nil)
	key := &PrivateKey{
		PrivateKey: priv,
		param:      param,
	}

	return key, err
}

//Sign sign data.
func (priv *PrivateKey) Sign(msg []byte) []byte {
	return ed25519.Sign(priv.PrivateKey, msg)
}

//Serialize serializes public key.
func (pub *PublicKey) Serialize() []byte {
	return []byte(pub.PublicKey)
}

//Serialize serializes private key.
func (priv *PrivateKey) Serialize() []byte {
	return []byte(priv.PrivateKey)
}

//PublicKey returns public key.
func (priv *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{
		PublicKey: ed25519.PublicKey(priv.PrivateKey[32:]),
		param:     priv.param,
	}
}

//addressBytes returns NEM address  bytes from PublicKey
func (pub *PublicKey) addressBytes() []byte {
	//Next we get a sha256 hash of the public key generated
	//via ECDSA, and then get a ripemd160 hash of the sha256 hash.
	shadPublicKeyBytes := sha3.KeccakSum256(pub.Serialize())

	ripeHash := ripemd160.New()
	if _, err := ripeHash.Write(shadPublicKeyBytes[:]); err != nil {
		panic(err)
	}
	return ripeHash.Sum(nil)
}

//Address returns NEM address from PublicKey
func (pub *PublicKey) Address() string {
	ripeHashedBytes := pub.addressBytes()
	ripeHashedBytes = append(ripeHashedBytes, 0x0)
	copy(ripeHashedBytes[1:], ripeHashedBytes[:len(ripeHashedBytes)-1])
	ripeHashedBytes[0] = pub.param
	shasum := sha3.KeccakSum256(ripeHashedBytes)
	adr := append(ripeHashedBytes, shasum[:4]...)

	adrstr := base32.StdEncoding.EncodeToString(adr)
	result := make([]rune, 0, len(adrstr)+len(adrstr)/6+1)
	for i, c := range adrstr {
		result = append(result, c)
		if (i+1)%6 == 0 {
			result = append(result, '-')
		}
	}
	return string(result)
}

//Verify verifies signature is valid or not.
func (pub *PublicKey) Verify(signature []byte, data []byte) bool {
	return ed25519.Verify(pub.PublicKey, data, signature)
}
