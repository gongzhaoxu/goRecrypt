package main

import (
	"fmt"
	"goRecrypt/curve"
	"goRecrypt/recrypt"
)

func main() {
	//-------------------------------预准备-------------------------------
	// Alice生成密钥对
	aPriKey, aPubKey, _ := curve.GenerateKeys()
	// Bob生成密钥对
	bPriKey, bPubKey, _ := curve.GenerateKeys()
	//明文
	m := "Hello, 巩钊旭的毕业设计"
	fmt.Println("origin message:", m)
	//-------------------------------加密---------------------------------
	// Alice加密，返回cipherText即m_enc 、capsule
	cipherText, capsule, err := recrypt.Encrypt(m, aPubKey)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("ciphereText:", cipherText)
	fmt.Println("capsule:", capsule)

	//-------------------------------重加密秘钥生成---------------------------------
	// Alice生成重加密秘钥rk
	rk, pubX, err := recrypt.ReKeyGen(aPriKey, bPubKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("rk:", rk)

	//-------------------------------代理执行重加密---------------------------------
	newCapsule, err := recrypt.ReEncryption(rk, capsule)
	if err != nil {
		fmt.Println(err.Error())
	}
	//-------------------------------解密---------------------------------
	// Bob解密原始明文
	plainText, err := recrypt.Decrypt(bPriKey, newCapsule, pubX, cipherText)
	if err != nil {
		fmt.Println(err)
	}

	// 输出 plainText
	fmt.Println("plainText:", string(plainText))

}
