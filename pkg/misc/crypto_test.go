/*
 * Copyright 2022 CECTC, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package misc

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAesEncryptGCM(t *testing.T) {
	fmt.Println(hex.EncodeToString([]byte("123456789abcdefg")))
	key, _ := hex.DecodeString("31323334353637383961626364656667")
	//key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	fmt.Println(string(key))
	plaintext := []byte("sunset3")
	//plaintext := []byte("exampleplaintext")
	//encrypted, err := AesEncryptGCM(plaintext, key, []byte("greatdbpack!"))
	encrypted, err := AesEncryptGCM(plaintext, key, []byte("greatdbpack!"))
	fmt.Println("encrypted: ", string(encrypted))
	assert.Nil(t, err)
	t.Logf("%x", encrypted)
}

func TestAesDecryptGCM(t *testing.T) {
	key, _ := hex.DecodeString("31323334353637383961626364656667")
	encrypted, _ := hex.DecodeString("8cc9106bfe89cb690265a3bb5caadcd88ea42ab8c035e8")
	decrypted, err := AesDecryptGCM(encrypted, key, []byte("greatdbpack!"))
	fmt.Println("decrypted: ", string(decrypted), "key: ", string(key), "encrypted: ", string(encrypted))
	assert.Nil(t, err)
	assert.Equal(t, []byte("sunset3"), decrypted)

	//key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	//encrypted, _ := hex.DecodeString("dbb2b731c2c7e9f637195ba70f85e6a26e5cbe3f536ad3457d72cf8cc4c66df1")
	//decrypted, err := AesDecryptGCM(encrypted, key, []byte("greatdbpack!"))
	//assert.Nil(t, err)
	//assert.Equal(t, []byte("exampleplaintext"), decrypted)
}

func TestAesEncryptCBC(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("exampleplaintext")
	encrypted, err := AesEncryptCBC(plaintext, key, []byte("impressivedbpack"))
	assert.Nil(t, err)
	t.Logf("%x", encrypted)
}

func TestAesDecryptCBC(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	encrypted, _ := hex.DecodeString("25d5fc99f3bf7313d6f96ef83c744240d0adc7f5ad1712359ac4335b1da33a4a")
	decrypted, err := AesDecryptCBC(encrypted, key, []byte("impressivedbpack"))
	assert.Nil(t, err)
	assert.Equal(t, []byte("exampleplaintext"), decrypted)
}

func TestAesEncryptECB(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("exampleplaintext")
	encrypted, err := AesEncryptECB(plaintext, key)
	assert.Nil(t, err)
	t.Logf("%x", encrypted)
}

func TestAesDecryptECB(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	encrypted, _ := hex.DecodeString("f42512e1e4039213bd449ba47faa1b749c2f799fae8d6a326ffff2489e0a7e8a")
	decrypted, err := AesDecryptECB(encrypted, key)
	assert.Nil(t, err)
	assert.Equal(t, []byte("exampleplaintext"), decrypted)
}

func TestAesEncryptCFB(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("exampleplaintext")
	encrypted, err := AesEncryptCFB(plaintext, key)
	assert.Nil(t, err)
	t.Logf("%x", encrypted)
}

func TestAesDecryptCFB(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	encrypted, _ := hex.DecodeString("a5ee2fa16e5f7328fd2077a19ca0d7038bb239e498962b2b51aa40f11f9bc2d4")
	decrypted, err := AesDecryptCFB(encrypted, key)
	assert.Nil(t, err)
	assert.Equal(t, []byte("exampleplaintext"), decrypted)
}

func TestSm4EncryptGCM(t *testing.T) {
	key, _ := hex.DecodeString("31323334353637383961626364656667")
	plaintext := []byte("sunset4")
	encrypted, err := Sm4EncryptGCM(plaintext, key, []byte("greatdbpack!"))
	assert.Nil(t, err)
	t.Logf("%x", encrypted)
}

func TestSm4DecryptGCM(t *testing.T) {
	key, _ := hex.DecodeString("31323334353637383961626364656667")
	encrypted, _ := hex.DecodeString("4b3dd6cb3e0145")
	decrypted, err := Sm4DecryptGCM(encrypted, key, []byte("greatdbpack!"))
	assert.Nil(t, err)
	t.Logf("%s", decrypted)
	assert.Equal(t, []byte("sunset4"), decrypted)
}

func TestSm4EncryptECB(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("exampleplaintext")
	encrypted, err := Sm4EncryptECB(plaintext, key)
	assert.Nil(t, err)
	t.Logf("%x", encrypted)
}

func TestSm4DecryptECB(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	encrypted, _ := hex.DecodeString("1cadd74166afbe5f4bdaf6ebb49d4c46ce96714d2c0839338f995f4854c61b58")
	decrypted, err := Sm4DecryptECB(encrypted, key)
	assert.Nil(t, err)
	assert.Equal(t, []byte("exampleplaintext"), decrypted)
}

func TestSm4EncryptCBC(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("exampleplaintext")
	encrypted, err := Sm4EncryptCBC(plaintext, key, []byte("impressivedbpack"))
	assert.Nil(t, err)
	t.Logf("%x", encrypted)
}

func TestSm4DecryptCBC(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	encrypted, _ := hex.DecodeString("2e88063cb32a13ce8fbfb60512c23d78d257734049682849d7c82a19f00e131a")
	decrypted, err := Sm4DecryptCBC(encrypted, key, []byte("impressivedbpack"))
	assert.Nil(t, err)
	assert.Equal(t, []byte("exampleplaintext"), decrypted)
}

func TestSm4EncryptCFB(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("exampleplaintext")
	encrypted, err := Sm4EncryptCFB(plaintext, key, []byte("impressivedbpack"))
	assert.Nil(t, err)
	t.Logf("%x", encrypted)
}

func TestSm4DecryptCFB(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	encrypted, _ := hex.DecodeString("5ce63f4fac3744073aa91ac44bdc4ab44a19895a9fcb106947eae2cecfd99e62")
	decrypted, err := Sm4DecryptCFB(encrypted, key, []byte("impressivedbpack"))
	assert.Nil(t, err)
	assert.Equal(t, []byte("exampleplaintext"), decrypted)
}

func TestSm4EncryptOFB(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("exampleplaintext")
	encrypted, err := Sm4EncryptOFB(plaintext, key, []byte("impressivedbpack"))
	assert.Nil(t, err)
	t.Logf("%x", encrypted)
}

func TestSm4DecryptOFB(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	encrypted, _ := hex.DecodeString("5ce63f4fac3744073aa91ac44bdc4ab4f83abab6ff8e4fd91da0740e339f9b2d")
	decrypted, err := Sm4DecryptOFB(encrypted, key, []byte("impressivedbpack"))
	assert.Nil(t, err)
	assert.Equal(t, []byte("exampleplaintext"), decrypted)
}
