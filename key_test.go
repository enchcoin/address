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
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"log"
	"strings"
	"testing"
)

func TestKeys3(t *testing.T) {
	cont, err := ioutil.ReadFile("1.test-keys.dat")
	if err != nil {
		t.Error(err)
	}
	for i, line := range strings.Split(string(cont), "\r\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		strs := strings.Split(strings.Replace(line, " ", "", -1), ":")
		if len(strs) < 4 {
			t.Error("data is not enough", "line ", i)
		}

		adr := strs[4]
		privBytes, err := hex.DecodeString(strs[1])
		if err != nil {
			t.Error(err, "line ", i)
		}
		pubBytes, err := hex.DecodeString(strs[3])
		if err != nil {
			t.Error(err, "line ", i)
		}
		for i := 0; i < len(privBytes)/2; i++ {
			privBytes[i], privBytes[len(privBytes)-1-i] = privBytes[len(privBytes)-1-i], privBytes[i]
		}
		key, err := NewPrivateKey(privBytes, MainNet)
		if err != nil {
			t.Error(err, "line ", i)
		}
		if !bytes.Equal(key.PublicKey().Serialize(), pubBytes) {
			t.Error("public key is not correct", " line", i)
		}
		cadr := strings.Replace(key.PublicKey().Address(), "-", "", -1)

		if adr != cadr {
			t.Error("adr not correct, correct:", adr, "wrong:", cadr)
		}
	}
}

func TestKeys2(t *testing.T) {
	adrCorrect := "NDSD3U-3XDUID-LGG73G-V6C7ZB-NOUVVB-S3QD7M-CBTD"
	privHex := "c009ee81c75898f63371f81cfa4463cb2cd82a11fdbdf5792404cf3bdf5f506b"
	pubHex := "2a36b1d783f4c35534215ceb61f2a2bf6df9a6b4eb70dc2d70320eccfedaad6a"
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		t.Error(err)
	}
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Error(err)
	}
	for i := 0; i < len(privBytes)/2; i++ {
		privBytes[i], privBytes[len(privBytes)-1-i] = privBytes[len(privBytes)-1-i], privBytes[i]
	}
	for i := 0; i < len(pubBytes)/2; i++ {
		//pubBytes[i], pubBytes[len(pubBytes)-1-i] = pubBytes[len(pubBytes)-1-i], pubBytes[i]
	}
	key, err := NewPrivateKey(privBytes, MainNet)
	if err != nil {
		t.Error(err)
	}
	log.Print(hex.EncodeToString(key.PublicKey().Serialize()))
	adr := key.PublicKey().Address()
	log.Println("address  =", adr)
	if adr != adrCorrect {
		t.Error("adr not correct")
	}
	if !bytes.Equal(key.PublicKey().Serialize(), pubBytes) {
		t.Error("public key is not correct")
	}
}

func TestKeys(t *testing.T) {
	key, err := Generate(MainNet)
	if err != nil {
		t.Error(err)
	}
	adr := key.PublicKey().Address()
	log.Println("address=", adr)

	pub2 := NewPublicKey(key.PublicKey().Serialize(), MainNet)

	if adr != pub2.Address() {
		t.Errorf("key unmatched")
	}

}

func TestSign(t *testing.T) {
	key, err := Generate(MainNet)
	if err != nil {
		t.Error(err)
	}
	data := []byte("test data")
	sig := key.Sign(data)
	if ok := key.PublicKey().Verify(sig, data); !ok {
		t.Error("cannot verify")
	}
	data2 := []byte("invalid test data")
	if ok := key.PublicKey().Verify(sig, data2); ok {
		t.Error("cannot verify")
	}
}

func TestSign2(t *testing.T) {
	cont, err := ioutil.ReadFile("2.test-sign.dat")
	if err != nil {
		t.Error(err)
	}
	for i, line := range strings.Split(string(cont), "\r\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		strs := strings.Split(strings.Replace(line, " ", "", -1), ":")
		if len(strs) < 5 {
			t.Error("data is not enough", "line ", i)
		}
		privBytes, err := hex.DecodeString(strs[1])
		if err != nil {
			t.Error(err, "line ", i)
		}
		for i := 0; i < len(privBytes)/2; i++ {
			privBytes[i], privBytes[len(privBytes)-1-i] = privBytes[len(privBytes)-1-i], privBytes[i]
		}
		pubBytes, err := hex.DecodeString(strs[2])
		if err != nil {
			t.Error(err, "line ", i)
		}
		sign, err := hex.DecodeString(strs[3])
		if err != nil {
			t.Error(err, "line ", i)
		}
		msg, err := hex.DecodeString(strs[5])
		if err != nil {
			t.Error(err, "line ", i)
		}

		key, err := NewPrivateKey(privBytes, MainNet)
		if err != nil {
			t.Error(err, "line ", i)
		}
		if !bytes.Equal(key.PublicKey().Serialize(), pubBytes) {
			t.Error("public key is not correct", " line", i)
		}

		if ok := key.PublicKey().Verify(sign, msg); !ok {
			t.Error("cannot verify")
		}
	}
}
