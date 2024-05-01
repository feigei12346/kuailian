package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

type DID string

// 公钥
type PubKey struct {
	ID           string `json:"id"`           // 公钥id
	Type         string `json:"type"`         // 公钥类型
	PublicKeyPem string `json:"publicKeyPem"` // 公钥
}

// 认证
type Auth struct {
	Type       string `json:"type"`
	AuthKeyPem string `json:"authKeyPem"`
}

// DID文档
type BasicDoc struct {
	ID             DID      `json:"id"`      // DID标识
	Type           int      `json:"type"`    // 链标识还是账户标识
	Created        uint64   `json:"created"` // 创建时间
	Updated        uint64   `json:"updated"`
	Controller     DID      `json:"controller"`
	PublicKey      []PubKey `json:"publicKey"`      // 公钥数组
	Authentication Auth     `json:"authentication"` // 认证数组
}

// 链文档
type ChainDoc struct {
	BasicDoc
	Extra []byte `json:"extra"` // for further usage
}

type Usercert struct {
	ID            DID    `json:"id"`      // DID标识
	Type          int    `json:"type"`    // 链标识还是账户标识
	Created       uint64 `json:"created"` // 创建时间
	Updated       uint64 `json:"updated"`
	Controller    DID    `json:"controller"`
	PublicKey     string `json:"publicKey"`     // 公钥
	Issuer        DID    `json:"issuer"`        //颁发者DID
	CertSignature string `json:"certsignature"` // 证书的签名
}

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
	return privkey, &privkey.PublicKey
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return string(pubkey_pem), nil
}

// doc都用结构体的方式存，然后再转为[]byte
func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("key type is not RSA")
}

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	return string(privkey_pem)
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}
func main() {
	priv, pub := GenerateRsaKeyPair()

	priv_pem := ExportRsaPrivateKeyAsPemStr(priv)
	pub_pem, _ := ExportRsaPublicKeyAsPemStr(pub)

	docID := "did_chain001_diyige"
	// 创建 BasicDoc 对象
	basicDoc := BasicDoc{
		ID:         DID(docID),
		Type:       1,
		Created:    123456789,
		Updated:    987654321,
		Controller: "controllerDID",
		PublicKey: []PubKey{
			{ID: "key1", Type: "RSA", PublicKeyPem: pub_pem},
			{ID: "key2", Type: "RSA", PublicKeyPem: pub_pem},
		},
		Authentication: Auth{Type: "RSA", AuthKeyPem: pub_pem},
	}

	// 使用 JSON 编码器将 BasicDoc 对象转换为 []byte
	docBytes, err := json.Marshal(basicDoc)
	if err != nil {
		fmt.Println("Error encoding BasicDoc:", err)
		return
	}

	//fmt.Println("basicDoc", basicDoc)
	//fmt.Println("pubkey", pub_pem)
	fmt.Println("prikey", priv_pem)
	//fmt.Println("Encoded BasicDoc as JSON:", docBytes)
	fmt.Println("Encoded BasicDoc as JSON:", string(docBytes))
	//保存私钥
	prikeyfilename := "D:\\证书文件\\私钥\\" + docID + "_privkeyPEM.pem"
	err = ioutil.WriteFile(prikeyfilename, []byte(priv_pem), 0644)
	if err != nil {
		panic(err)
	}
	// 要签名的消息
	message := []byte("Hello:?_RSA")
	// 计算消息的哈希值
	hashed := sha256.Sum256(message)

	// 使用私钥对消息的哈希值进行签名
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Println("Error signing:", err)
		return
	}
	//fmt.Println(string(message))

	//编码  对消息的哈希进行编码 给智能合约传入此参数进行验证
	base64messagehash := base64.StdEncoding.EncodeToString(hashed[:])
	base64Signature := base64.StdEncoding.EncodeToString(signature)
	fmt.Println("Base64 Encoded messagehash(用于调用智能合约的消息参数):", base64messagehash)
	fmt.Println("Base64 Encoded Signature(用于调用智能合约的消息签名参数):", base64Signature)
	//fmt.Println(signature)

	messagehashBytes, err := base64.StdEncoding.DecodeString(base64messagehash)
	if err != nil {
		fmt.Println("Error decoding Base64 string:", err)

	}
	// 解码 Base64 编码的字符串为字节切片
	signatureBytes, err := base64.StdEncoding.DecodeString(base64Signature)
	if err != nil {
		fmt.Println("Error decoding Base64 string:", err)
	}

	var doc ChainDoc
	if err = json.Unmarshal(docBytes, &doc); err != nil {

	}

	auth := doc.Authentication
	//PEM格式的公钥字符串

	//authkeyType := auth.Type
	authkey := auth.AuthKeyPem
	fmt.Println("PEM格式的账户公钥：", authkey)
	//parsedKey, _ := ParseRsaPublicKeyFromPemStr(authkey)
	// 解码 PEM 格式的公钥
	// block, _ := pem.Decode([]byte(authkey))
	// if block == nil {
	// 	fmt.Println("pem解码错误")
	// }

	// // 解析DER格式的公钥
	// parsedKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	// if err != nil {
	// 	fmt.Println("der解码错误")
	// }
	block, _ := pem.Decode([]byte(authkey))
	if block == nil {
		fmt.Println("pem解码错误")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println("der解码错误")
	}

	err = rsa.VerifyPKCS1v15(parsedKey.(*rsa.PublicKey), crypto.SHA256, messagehashBytes, signatureBytes)
	if err != nil {
		fmt.Println("签名验证失败")

	}
	// 签名验证成功
	fmt.Println("签名验证成功")

	//__________生成证书签名————————————————————-
	docSign := []byte(docID + authkey)
	dochashed := sha256.Sum256(docSign)
	issuerDID := "root"
	//取出root的私钥对证书进行签名
	issuerPrikeyfilename := "D:\\证书文件\\私钥\\" + issuerDID + "_privkeyPEM.pem"
	jsonissuerPrikeyData, err := ioutil.ReadFile(issuerPrikeyfilename)
	if err != nil {
		panic(err)
	}
	issuerPriv, err := ParseRsaPrivateKeyFromPemStr(string(jsonissuerPrikeyData))

	// 使用颁发者的私钥对证书的哈希值进行签名
	docsignature, err := rsa.SignPKCS1v15(rand.Reader, issuerPriv, crypto.SHA256, dochashed[:])
	if err != nil {
		fmt.Println("证书签名失败", err)
		return
	}
	base64docSignature := base64.StdEncoding.EncodeToString(docsignature)
	fmt.Println("证书签名为:", base64docSignature)
	fmt.Println("账户DID为：", docID)
	fmt.Println("账户公钥为:", authkey)
	fmt.Println("颁发者DID为", issuerDID)
	//将证书文件写入本地
	identity := Usercert{
		ID:            DID(docID),
		Type:          0,
		Created:       0,
		Updated:       0,
		Controller:    DID(docID),
		PublicKey:     authkey,            // 公钥
		Issuer:        DID(issuerDID),     //颁发者DID
		CertSignature: base64docSignature, // 证书的签名
	}
	jsonCertData, err := json.Marshal(identity)
	if err != nil {
		panic(err)
	}
	certfilename := "D:\\证书文件\\" + docID + "cert.json"
	err = ioutil.WriteFile(certfilename, jsonCertData, 0644)
	if err != nil {
		panic(err)
	}

	//从本地读出文件并进行签名验证
	// jsonCertData, err = ioutil.ReadFile(certfilename)
	// if err != nil {
	// 	panic(err)
	// }
	// var storedIdentity Usercert
	// err = json.Unmarshal(jsonCertData, &storedIdentity)
	// if err != nil {
	// 	panic(err)
	// }
	// block1, _ := pem.Decode([]byte(storedIdentity.PublicKey))
	// if block1 == nil {
	// 	fmt.Println("保存文件中pem解码错误")
	// }
	// if block.Type == block1.Type && bytes.Equal(block.Bytes, block1.Bytes) {
	// 	fmt.Println("两个 pem.Block 结构体相等")
	// } else {
	// 	fmt.Println("两个 pem.Block 结构体不相等")
	// }
	// fmt.Println(authkey == storedIdentity.PublicKey)
	// parsedKey1, err := x509.ParsePKIXPublicKey(block1.Bytes)

	// if err != nil {
	// 	fmt.Println("保存文件中der解码错误")
	// }
	// if reflect.DeepEqual(parsedKey, parsedKey1) {
	// 	fmt.Println("两个公钥相等")
	// } else {
	// 	fmt.Println("两个公钥不相等")
	// }
	//验证一下证书签名
	docsignatureBytes, err := base64.StdEncoding.DecodeString(identity.CertSignature)
	//docsignatureBytes1, err := base64.StdEncoding.DecodeString(identity.CertSignature)
	fmt.Println(base64docSignature == identity.CertSignature)
	//取颁发者的证书
	issuerCertfilename := "D:\\证书文件\\" + issuerDID + "cert.json"
	jsonissuerCertData, err := ioutil.ReadFile(issuerCertfilename)
	if err != nil {
		panic(err)
	}
	var issuerStoredIdentity Usercert
	err = json.Unmarshal(jsonissuerCertData, &issuerStoredIdentity)
	if err != nil {
		panic(err)
	}
	//对pem的颁发者公钥进行解析
	issuerPubkey, err := ParseRsaPublicKeyFromPemStr(issuerStoredIdentity.PublicKey)
	//使用颁发者的公钥进行证书的验证
	err = rsa.VerifyPKCS1v15(issuerPubkey, crypto.SHA256, dochashed[:], docsignatureBytes)
	if err != nil {
		fmt.Println(err)
		fmt.Println("签名验证失败")

	}
	// 签名验证成功
	fmt.Println("签名验证成功")
	//DID标识生成

	//身份验证协议

	//测试验证
	// var doc ChainDoc
	// if err = json.Unmarshal(docBytes, &doc); err != nil {
	// 	fmt.Println("转换错误")
	// }
	// if pub_pem != doc.Authentication.AuthKeyPem {
	// 	fmt.Println("不匹配")
	// } else {
	// 	fmt.Println("Success")
	// }

	// fmt.Println(pub_pem)
	// fmt.Println(doc.Authentication.AuthKeyPem)
}
