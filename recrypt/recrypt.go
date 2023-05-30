package recrypt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"goRecrypt/curve"
	"goRecrypt/math"
	"goRecrypt/utils"
	"math/big"
)

type Capsule struct {
	E *ecdsa.PublicKey
	V *ecdsa.PublicKey
	S *big.Int
}

// 生成capsule和aes对称密钥keyBytes，即K
func encryptKeyGen(pubKey *ecdsa.PublicKey) (capsule *Capsule, keyBytes []byte, err error) {
	s := new(big.Int)
	// 生成 E,V 密钥对
	priE, pubE, err := curve.GenerateKeys()
	priV, pubV, err := curve.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}
	// H2(E || V)
	h := utils.HashToCurve(
		utils.ConcatBytes(
			curve.PointToBytes(pubE),
			curve.PointToBytes(pubV)))
	// s = v + e * H2(E || V)
	s = math.BigIntAdd(priV.D, math.BigIntMul(priE.D, h))
	// (pk_A)^{e+v}
	point := curve.PointScalarMul(pubKey, math.BigIntAdd(priE.D, priV.D))
	// 生成aes对称密钥keyBytes，即K
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, nil, err
	}
	capsule = &Capsule{
		E: pubE,
		V: pubV,
		S: s,
	}
	fmt.Println("对称密钥字节流:", hex.EncodeToString(keyBytes))
	return capsule, keyBytes, nil
}

// Recreate aes key
func RecreateAESKeyByMyPriKey(capsule *Capsule, aPriKey *ecdsa.PrivateKey) (keyBytes []byte, err error) {
	point1 := curve.PointScalarAdd(capsule.E, capsule.V)
	point := curve.PointScalarMul(point1, aPriKey.D)
	// generate aes key
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

func RecreateAESKeyByMyPriKeyStr(capsule *Capsule, aPriKeyStr string) (keyBytes []byte, err error) {
	aPriKey, err := utils.PrivateKeyStrToKey(aPriKeyStr)
	if err != nil {
		return nil, err
	}
	return RecreateAESKeyByMyPriKey(capsule, aPriKey)
}

func EncryptMessageByAESKey(message []byte, keyBytes []byte) (cipherText []byte, err error) {
	key := hex.EncodeToString(keyBytes)
	// use aes gcm algorithm to encrypt
	// mark keyBytes[:12] as nonce
	cipherText, err = GCMEncrypt(message, key[:32], keyBytes[:12], nil)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

// 加密密文，返回cipherText即m_enc 、capsule
// AES + Proxy Re-Encryption
func Encrypt(message string, pubKey *ecdsa.PublicKey) (cipherText []byte, capsule *Capsule, err error) {
	// 生成capsule和aes对称密钥keyBytes，即K
	capsule, keyBytes, err := encryptKeyGen(pubKey)
	if err != nil {
		return nil, nil, err
	}
	key := hex.EncodeToString(keyBytes)
	// 使用aes-gcm算法加密消息m生成cipherText，即论文中的m_enc
	//标记keyBytes[:12]为随机数
	cipherText, err = GCMEncrypt([]byte(message), key[:32], keyBytes[:12], nil)
	if err != nil {
		return nil, nil, err
	}
	return cipherText, capsule, nil
}

func EncryptByStr(message, pubKeyStr string) (cipherText []byte, capsule *Capsule, err error) {
	key, err := utils.PublicKeyStrToKey(pubKeyStr)
	if err != nil {
		return nil, nil, err
	}
	return Encrypt(message, key)
}

// encrypt file
func EncryptFile(inputFile, outPutFile string, pubKey *ecdsa.PublicKey) (capsule *Capsule, err error) {
	capsule, keyBytes, err := encryptKeyGen(pubKey)
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(keyBytes)
	// use aes ofb algorithm to encrypt
	// mark keyBytes[:16] as nonce
	err = OFBFileEncrypt(key[:32], keyBytes[:16], inputFile, outPutFile)
	if err != nil {
		return nil, err
	}
	return capsule, nil
}

// encrypt file by pubkey str
func EncryptFileByStr(inputFile, outPutFile, pubKeyStr string) (capsule *Capsule, err error) {
	key, err := utils.PublicKeyStrToKey(pubKeyStr)
	if err != nil {
		return nil, err
	}
	return EncryptFile(inputFile, outPutFile, key)
}

// Alice生成重加密秘钥发给代理
// rk = sk_A * d^{-1}
func ReKeyGen(aPriKey *ecdsa.PrivateKey, bPubKey *ecdsa.PublicKey) (*big.Int, *ecdsa.PublicKey, error) {
	//  x,X key-pair
	priX, pubX, err := curve.GenerateKeys()
	if err != nil {
		return nil, nil, err
	}
	//  d = H3(X_A || pk_B || pk_B^{x_A})
	point := curve.PointScalarMul(bPubKey, priX.D)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pubX),
				curve.PointToBytes(bPubKey)),
			curve.PointToBytes(point)))
	// rk = sk_A * d^{-1}
	rk := math.BigIntMul(aPriKey.D, math.GetInvert(d))
	rk.Mod(rk, curve.N)
	return rk, pubX, nil
}

func ReKeyGenByStr(aPriKeyStr, bPubKeyStr string) (*big.Int, *ecdsa.PublicKey, error) {
	aPriKey, err := utils.PrivateKeyStrToKey(aPriKeyStr)
	if err != nil {
		return nil, nil, err
	}
	bPubKey, err := utils.PublicKeyStrToKey(bPubKeyStr)
	if err != nil {
		return nil, nil, err
	}
	return ReKeyGen(aPriKey, bPubKey)
}

// 代理执行代理重加密算法
func ReEncryption(rk *big.Int, capsule *Capsule) (*Capsule, error) {
	//检查 g^s 是否等于 V * E^{H2(E || V)}
	x1, y1 := curve.CURVE.ScalarBaseMult(capsule.S.Bytes())
	tempX, tempY := curve.CURVE.ScalarMult(capsule.E.X, capsule.E.Y,
		utils.HashToCurve(
			utils.ConcatBytes(
				curve.PointToBytes(capsule.E),
				curve.PointToBytes(capsule.V))).Bytes())
	x2, y2 := curve.CURVE.Add(capsule.V.X, capsule.V.Y, tempX, tempY)
	// 如果检查失败返回错误
	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		return nil, fmt.Errorf("%s", "Capsule not match")
	}
	// E' = E^{rk}, V' = V^{rk}
	newCapsule := &Capsule{
		E: curve.PointScalarMul(capsule.E, rk),
		V: curve.PointScalarMul(capsule.V, rk),
		S: capsule.S,
	}
	return newCapsule, nil
}

// Bob解密对称密钥keyBytes字节流
func decryptKeyGen(bPriKey *ecdsa.PrivateKey, capsule *Capsule, pubX *ecdsa.PublicKey) (keyBytes []byte, err error) {
	// S = X_A^{sk_B}
	S := curve.PointScalarMul(pubX, bPriKey.D)
	// recreate d = H3(X_A || pk_B || S)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(pubX),
				curve.PointToBytes(&bPriKey.PublicKey)),
			curve.PointToBytes(S)))
	point := curve.PointScalarMul(
		curve.PointScalarAdd(capsule.E, capsule.V), d)
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point))
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

// 计算得到对称秘钥K，用K解密m_enc得到明文
func Decrypt(bPriKey *ecdsa.PrivateKey, capsule *Capsule, pubX *ecdsa.PublicKey, cipherText []byte) (plainText []byte, err error) {
	// 得到对称密钥K,即keyBytes
	keyBytes, err := decryptKeyGen(bPriKey, capsule, pubX)
	if err != nil {
		return nil, err
	}
	// recreate aes key = G((E' * V')^d)
	key := hex.EncodeToString(keyBytes)
	// 使用aes-gcm解密
	//标记keyBytes[:12]为随机数
	plainText, err = GCMDecrypt(cipherText, key[:32], keyBytes[:12], nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func DecryptByStr(bPriKeyStr string, capsule *Capsule, pubXStr string, cipherText []byte) (plainText []byte, err error) {
	bPriKey, err := utils.PrivateKeyStrToKey(bPriKeyStr)
	if err != nil {
		return nil, err
	}
	pubX, err := utils.PublicKeyStrToKey(pubXStr)
	if err != nil {
		return nil, err
	}
	return Decrypt(bPriKey, capsule, pubX, cipherText)
}

// decrypt file
func DecryptFile(inputFile, outPutFile string, bPriKey *ecdsa.PrivateKey, capsule *Capsule, pubX *ecdsa.PublicKey) (err error) {
	keyBytes, err := decryptKeyGen(bPriKey, capsule, pubX)
	if err != nil {
		return err
	}
	key := hex.EncodeToString(keyBytes)
	// use aes gcm to decrypt
	// mark keyBytes[:16] as nonce
	err = OFBFileDecrypt(key[:32], keyBytes[:16], inputFile, outPutFile)
	if err != nil {
		return err
	}
	return nil
}

// decrypt file by str
func DecryptFileByStr(inputFile, outPutFile string, bPriKeyStr string, capsule *Capsule, pubXStr string) (err error) {
	bPriKey, err := utils.PrivateKeyStrToKey(bPriKeyStr)
	if err != nil {
		return err
	}
	pubX, err := utils.PublicKeyStrToKey(pubXStr)
	if err != nil {
		return err
	}
	return DecryptFile(inputFile, outPutFile, bPriKey, capsule, pubX)
}

// Decrypt by my own private key
func DecryptOnMyPriKey(aPriKey *ecdsa.PrivateKey, capsule *Capsule, cipherText []byte) (plainText []byte, err error) {
	keyBytes, err := RecreateAESKeyByMyPriKey(capsule, aPriKey)
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(keyBytes)
	// use aes gcm algorithm to encrypt
	// mark keyBytes[:12] as nonce
	plainText, err = GCMDecrypt(cipherText, key[:32], keyBytes[:12], nil)
	return plainText, err
}

func DecryptOnMyOwnStrKey(aPriKeyStr string, capsule *Capsule, cipherText []byte) (plainText []byte, err error) {
	aPriKey, err := utils.PrivateKeyStrToKey(aPriKeyStr)
	if err != nil {
		return nil, err
	}
	return DecryptOnMyPriKey(aPriKey, capsule, cipherText)
}

func EncodeCapsule(capsule Capsule) (capsuleAsBytes []byte, err error) {
	gob.Register(elliptic.P256())
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err = enc.Encode(capsule); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func DecodeCapsule(capsuleAsBytes []byte) (capsule Capsule, err error) {
	capsule = Capsule{}
	gob.Register(elliptic.P256())
	dec := gob.NewDecoder(bytes.NewBuffer(capsuleAsBytes))
	if err = dec.Decode(&capsule); err != nil {
		return capsule, err
	}
	return capsule, nil
}
