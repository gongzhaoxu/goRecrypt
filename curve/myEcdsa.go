package curve

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
)

// 该文件提供生成公私钥密钥对的功能
// 并完成ECDSA的签名与验证

// 创建公私钥对
func GenerateKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// ECDSA签名
func Sign(privateKeyStr string, messageHash string) (string, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyStr)
	if err != nil {
		return "", err
	}
	privateKey, err := x509.ParseECPrivateKey(privateKeyBytes)
	if err != nil {
		return "", err
	}
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, []byte(messageHash))
	if err != nil {
		return "", err
	}
	rStr, _ := r.MarshalText()
	sStr, _ := s.MarshalText()
	var result bytes.Buffer
	w := gzip.NewWriter(&result)
	defer w.Close()
	_, err = w.Write([]byte(string(rStr) + "+" + string(sStr)))
	if err != nil {
		return "", err
	}
	w.Flush()
	return hex.EncodeToString(result.Bytes()), nil
}

// ECDSA验证
func Verify(messageHash, signature string, publicKey string) (bool, error) {
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return false, err
	}
	pubKey, _ := x509.ParsePKIXPublicKey(publicKeyBytes)
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, err
	}
	reader, err := gzip.NewReader(bytes.NewBuffer(sigBytes))
	if err != nil {
		return false, err
	}
	defer reader.Close()
	buf := make([]byte, 1024)
	count, err := reader.Read(buf)
	if err != nil {
		return false, err
	}
	rsArr := strings.Split(string(buf[:count]), "+")
	if len(rsArr) != 2 {
		return false, err
	}
	var r, s big.Int
	err = r.UnmarshalText([]byte(rsArr[0]))
	if err != nil {
		return false, err
	}
	err = s.UnmarshalText([]byte(rsArr[1]))
	if err != nil {
		return false, err
	}
	result := ecdsa.Verify(pubKey.(*ecdsa.PublicKey), []byte(messageHash), &r, &s)
	return result, nil
}
