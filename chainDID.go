package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"

	"chainmaker.org/chainmaker/contract-sdk-go/v2/pb/protogo"
	"chainmaker.org/chainmaker/contract-sdk-go/v2/sandbox"
	"chainmaker.org/chainmaker/contract-sdk-go/v2/sdk"
)

type ChainDID struct {
}

type DID string

// 公钥
type PubKey struct {
	ID           string `json:"id"`           //公钥id
	Type         string `json:"type"`         //公钥类型
	PublicKeyPem string `json:"publicKeyPem"` //公钥
}

// 认证
type Auth struct {
	Type       string `json:"type"`
	AuthKeyPem string `json:"authKeyPem"`
}

// DID文档
type BasicDoc struct {
	ID DID `json:"id"` //DID标识
	// Type           int      `json:"type"`    //链标识还是账户标识
	// Created        uint64   `json:"created"` //创建时间
	// Updated        uint64   `json:"updated"`
	// Controller     DID      `json:"controller"`
	// PublicKey      []PubKey `json:"publicKey"`      //公钥数组
	Authentication string `json:"authentication"` //认证数组
}

// 链文档
type ChainDoc struct {
	BasicDoc
	Extra []byte `json:"extra"` // for further usage
}

func (f *ChainDID) InitContract() protogo.Response {
	return sdk.Success([]byte("Init contract success"))
}

func (f *ChainDID) UpgradeContract() protogo.Response {
	return sdk.Success([]byte("Upgrade contract success"))
}

func (f *ChainDID) InvokeContract(method string) protogo.Response {
	switch method {
	case "ApplyDID":
		return f.ApplyDID()
	case "RegisterDIDDoc":
		return f.RegisterDIDDoc()
	case "ResolveDIDDoc":
		return f.ResolveDIDDoc()
	default:
		return sdk.Error("invalid method")
	}
}

func NewDoc(did DID, auth string) *BasicDoc {
	doc := &BasicDoc{
		ID:             did,
		Authentication: auth,
	}
	return doc
}

// 申请DID标识，检查是否合法，是否存在
func (f *ChainDID) ApplyDID() protogo.Response {
	params := sdk.Instance.GetArgs()
	//传来的是bytes需要转为string
	chaindid := string(params["chain_did"])
	//获取到要注册的did，检查是否已经存在，若不存在
	// err := sdk.Instance.PutStateByte("chain_did", chaindid, []byte(chaindid))
	// if err != nil {
	// 	return sdk.Error("fail to save fact bytes")
	// }
	return sdk.Success([]byte(chaindid + "success"))

}

// 注册DID文档 参数：did、doc
func (f *ChainDID) RegisterDIDDoc() protogo.Response {
	params := sdk.Instance.GetArgs()
	chaindid := string(params["chain_did"])
	//[]byte doc
	chainauth := string(params["chain_auth"])
	chaindoc := NewDoc(DID(chaindid), chainauth)

	docBytes, err := json.Marshal(chaindoc)
	if err != nil {
		return sdk.Error(fmt.Sprintf("marshal fact failed, err: %s", err))
	}

	sdk.Instance.EmitEvent("topic_vx", []string{string(chaindoc.ID), chaindoc.Authentication})

	//存储数据
	err1 := sdk.Instance.PutStateByte("chain_doc", string(chaindoc.ID), docBytes)
	if err1 != nil {
		return sdk.Error("fail to save DIDdoc bytes")
	}

	// 记录日志
	sdk.Instance.Infof("[save] chain_did=" + chaindid)
	sdk.Instance.Infof("[save] fileName=" + chainauth)

	return sdk.Success([]byte(chaindid + " success"))

}

func (f *ChainDID) finddocbyDID() protogo.Response {
	//params := sdk.Instance.GetArgs()
	chaindid := string(sdk.Instance.GetArgs()["chain_did"])
	//通过did获取到doc
	//chaindid := string(params["chain_did"])
	//所有的参数传过来都是[]byte类型

	result, err := sdk.Instance.GetStateByte("chain_doc", chaindid)
	if err != nil {
		return sdk.Error("failed to call get_state")
	}
	//公钥以pem string形式存进结构体，然后结构体转为[]byte
	//反序列化 将[]byte doc 解析为结构体
	var doc BasicDoc
	if err = json.Unmarshal(result, &doc); err != nil {
		return sdk.Error(fmt.Sprintf("unmarshal fact failed, err: %s", err))
	}

	// 记录日志
	sdk.Instance.Infof("[find_by_chain_did] chaindid=" + string(doc.ID))
	sdk.Instance.Infof("[find_by_chain_did] chainauth=" + doc.Authentication)

	return sdk.Success(result)

}

// 解析DID并认证  参数：chaindid、私钥签名后的消息
func (f *ChainDID) ResolveDIDDoc() protogo.Response {
	params := sdk.Instance.GetArgs()

	//通过did获取到doc
	chaindid := string(params["chain_did"])
	//所有的参数传过来都是[]byte类型

	message := string(params["message"])

	signature := string(params["signature"])

	messagehashBytes, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		fmt.Println("Error decoding Base64 string:", err)
		return sdk.Error("i")
	}

	// 解码 Base64 编码的字符串为字节切片
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		fmt.Println("Error decoding Base64 string:", err)
		return sdk.Error("i")
	}

	result, err := sdk.Instance.GetStateByte("chain_doc", chaindid)
	if err != nil {
		return sdk.Error("failed to call get_state")
	}

	//公钥以pem string形式存进结构体，然后结构体转为[]byte
	//反序列化 将[]byte doc 解析为结构体
	var doc BasicDoc
	if err = json.Unmarshal(result, &doc); err != nil {
		return sdk.Error(fmt.Sprintf("unmarshal fact failed, err: %s", err))
	}

	// 记录日志
	sdk.Instance.Infof("[find_by_chain_did] chaindid=" + string(doc.ID))
	sdk.Instance.Infof("[find_by_chain_did] chainauth=" + doc.Authentication)

	//获取到用于验证的公钥的id，再根据这个id获取到type和具体的公钥。

	//这部分的格式需要再定义一下
	auth := doc.Authentication
	//PEM格式的公钥字符串

	//authkeyType := auth.Type
	authkey := auth

	// 解码 PEM 格式的公钥
	block, _ := pem.Decode([]byte(authkey))
	if block == nil {
		return sdk.Error("Failed to decode PEM block")
	}

	// 解析DER格式的公钥
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return sdk.Error("Error parsing public key")
	}

	// 计算消息的哈希值
	//hash := sha256.Sum256(messagehashbyte)

	//signatureBytes=[]byte{100 66 12 210 200 194 220 76 32 155 37 211 107 92 231 135 44 105 50 119 116 154 174 31 30 224 23 189 102 203 161 220 181 62 138 121 127 125 177 173 45 184 129 154 166 45 2 192 16 189 218 161 161 22 192 31 24 96 24 61 142 186 99 180 154 213 219 90 194 149 199 242 117 156 93 80 48 36 98 166 4 192 232 208 190 54 132 26 201 158 247 153 48 91 39 198 110 194 46 68 252 84 4 52 92 223 81 65 251 177 233 139 224 16 255 243 107 167 114 47 48 244 91 101 103 111 76 2 54 99 62 32 214 223 120 76 119 54 10 235 70 95 72 41 107 133 25 146 31 119 19 46 149 25 75 23 204 69 162 212 93 80 47 165 207 119 131 46 158 119 243 167 73 10 149 185 17 236 219 211 36 65 167 43 81 205 134 234 189 132 137 166 99 125 5 240 55 61 167 84 216 119 192 228 243 240 59 136 89 77 19 23 52 62 209 250 249 224 179 72 28 45 210 16 98 13 187 131 65 225 188 158 32 159 251 57 236 25 227 221 3 224 21 226 221 133 206 74 169 8 104 99 220 21 179 29 14 220 185 202 164 214 208 54 131 141 26 50 224 147 8 133 93 192 204 241 169 195 130 89 86 23 50 36 68 126 69 245 205 248 79 121 213 0 111 212 78 249 6 137 2 103 178 22 190 37 58 144 53 157 193 228 233 116 137 106 15 233 177 40 163 230 214 188 129 175 237 13 201 234 137 67 209 166 71 241 100 154 189 24 211 128 104 116 26 88 222 70 165 244 231 50 217 225 232 113 6 92 170 168 130 37 164 76 53 70 43 126 194 145 158 208 224 88 184 131 252 177 40 204 217 189 50 3 164 41 161 141 243 26 13 85 43 225 154 236 44 24 200 234 43 95 213 199 38 79 133 5 143 126 27 188 137 241 153 194 199 128 67 245 226 159 9 202 30 128 203 155 66 129 218 46 12 64 250 50 220 39 51 177 121 77 226 141 138 52 97 42 161 194 105 25 8 252 174 172 61 82 169 209 45 114 165 5 36 140 72 117 33 251 214 152 106 125 123 12 68 142 18 58 183 212 90 123 94 32 221 89 84 210 3 214 157 11 41 165 245 92 135 33 39 232 148 240 147 82 51 239 231 175 217 54}

	// 验证签名
	err = rsa.VerifyPKCS1v15(parsedKey.(*rsa.PublicKey), crypto.SHA256, messagehashBytes, signatureBytes)
	if err != nil {
		sdk.Instance.Infof("签名验证失败")

		return sdk.Error("Signature verification failed")
	}
	// 签名验证成功
	sdk.Instance.Infof("签名验证成功")
	return sdk.Success([]byte("Signature verification successful"))

}

// main
func main() {
	err := sandbox.Start(new(ChainDID))
	if err != nil {
		log.Fatal(err)
	}
}
