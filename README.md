# sm-crypto

国密算法sm2、sm3和sm4的js实现。

## 安装

```bash
npm install --save sm-crypto
```

## sm2

### 获取密钥对

```js
const sm2 = require('sm-crypto').sm2

let keypair = sm2.generateKeyPairHex()

publicKey = keypair.publicKey // 公钥
privateKey = keypair.privateKey // 私钥

// 默认生成公钥 130 位太长，可以压缩公钥到 66 位
const compressedPublicKey = sm2.compressPublicKeyHex(publicKey) // compressedPublicKey 和 publicKey 等价
sm2.comparePublicKeyHex(publicKey, compressedPublicKey) // 判断公钥是否等价

// 自定义随机数，参数会直接透传给 jsbn 库的 BigInteger 构造器
// 注意：开发者使用自定义随机数，需要自行确保传入的随机数符合密码学安全
let keypair2 = sm2.generateKeyPairHex('123123123123123')
let keypair3 = sm2.generateKeyPairHex(256, SecureRandom)

let verifyResult = sm2.verifyPublicKey(publicKey) // 验证公钥
verifyResult = sm2.verifyPublicKey(compressedPublicKey) // 验证公钥
```

### 加密解密

```js
const sm2 = require('sm-crypto').sm2
const cipherMode = 1 // 1 - C1C3C2，0 - C1C2C3，默认为1

let encryptData = sm2.doEncrypt(msgString, publicKey, cipherMode) // 加密结果
let decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode) // 解密结果

encryptData = sm2.doEncrypt(msgArray, publicKey, cipherMode) // 加密结果，输入数组
decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode, {output: 'array'}) // 解密结果，输出数组
```

> ps：密文会在解密时自动补充 `04`，如遇到其他工具补充的 `04` 需手动去除再传入。

### 签名验签

> ps：理论上来说，只做纯签名是最快的。

```js
const sm2 = require('sm-crypto').sm2

// 纯签名 + 生成椭圆曲线点
let sigValueHex = sm2.doSignature(msg, privateKey) // 签名
let verifyResult = sm2.doVerifySignature(msg, sigValueHex, publicKey) // 验签结果

// 纯签名
let sigValueHex2 = sm2.doSignature(msg, privateKey, {
    pointPool: [sm2.getPoint(), sm2.getPoint(), sm2.getPoint(), sm2.getPoint()], // 传入事先已生成好的椭圆曲线点，可加快签名速度
}) // 签名
let verifyResult2 = sm2.doVerifySignature(msg, sigValueHex2, publicKey) // 验签结果

// 纯签名 + 生成椭圆曲线点 + der编解码
let sigValueHex3 = sm2.doSignature(msg, privateKey, {
    der: true,
}) // 签名
let verifyResult3 = sm2.doVerifySignature(msg, sigValueHex3, publicKey, {
    der: true,
}) // 验签结果

// 纯签名 + 生成椭圆曲线点 + sm3杂凑
let sigValueHex4 = sm2.doSignature(msg, privateKey, {
    hash: true,
}) // 签名
let verifyResult4 = sm2.doVerifySignature(msg, sigValueHex4, publicKey, {
    hash: true,
}) // 验签结果

// 纯签名 + 生成椭圆曲线点 + sm3杂凑（不做公钥推导）
let sigValueHex5 = sm2.doSignature(msg, privateKey, {
    hash: true,
    publicKey, // 传入公钥的话，可以去掉sm3杂凑中推导公钥的过程，速度会比纯签名 + 生成椭圆曲线点 + sm3杂凑快
})
let verifyResult5 = sm2.doVerifySignature(msg, sigValueHex5, publicKey, {
    hash: true,
    publicKey,
})

// 纯签名 + 生成椭圆曲线点 + sm3杂凑 + 不做公钥推 + 添加 userId（长度小于 8192）
// 默认 userId 值为 1234567812345678
let sigValueHex6 = sm2.doSignature(msgString, privateKey, {
    hash: true,
    publicKey,
    userId: 'testUserId',
})
let verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
    hash: true,
    userId: 'testUserId',
})
```

### 获取椭圆曲线点

```js
const sm2 = require('sm-crypto').sm2

let point = sm2.getPoint() // 获取一个椭圆曲线点，可在sm2签名时传入
```

### 根据私钥获取公钥

```js
const sm2 = require('sm-crypto).sm2

let publicKey = sm2.getPublicKeyFromPrivateKey(privateKey)
```

## sm3

```js
const sm3 = require('sm-crypto').sm3

let hashData = sm3('abc') // 杂凑

// hmac
hashData = sm3('abc', {
    key: 'daac25c1512fe50f79b0e4526b93f5c0e1460cef40b6dd44af13caec62e8c60e0d885f3c6d6fb51e530889e6fd4ac743a6d332e68a0f2a3923f42585dceb93e9', // 要求为 16 进制串或字节数组
})
```

## sm4

### 加密

```js
const sm4 = require('sm-crypto').sm4
const msg = 'hello world! 我是 juneandgreen.' // 可以为 utf8 串或字节数组
const key = '0123456789abcdeffedcba9876543210' // 可以为 16 进制串或字节数组，要求为 128 比特

let encryptData = sm4.encrypt(msg, key) // 加密，默认输出 16 进制字符串，默认使用 pkcs#7 填充（传 pkcs#5 也会走 pkcs#7 填充）
let encryptData = sm4.encrypt(msg, key, {padding: 'none'}) // 加密，不使用 padding
let encryptData = sm4.encrypt(msg, key, {padding: 'none', output: 'array'}) // 加密，不使用 padding，输出为字节数组
let encryptData = sm4.encrypt(msg, key, {mode: 'cbc', iv: 'fedcba98765432100123456789abcdef'}) // 加密，cbc 模式
```

### 解密

```js
const sm4 = require('sm-crypto').sm4
const encryptData = '0e395deb10f6e8a17e17823e1fd9bd98a1bff1df508b5b8a1efb79ec633d1bb129432ac1b74972dbe97bab04f024e89c' // 可以为 16 进制串或字节数组
const key = '0123456789abcdeffedcba9876543210' // 可以为 16 进制串或字节数组，要求为 128 比特

let decryptData = sm4.decrypt(encryptData, key) // 解密，默认输出 utf8 字符串，默认使用 pkcs#7 填充（传 pkcs#5 也会走 pkcs#7 填充）
let decryptData = sm4.decrypt(encryptData, key, {padding: 'none'}) // 解密，不使用 padding
let decryptData = sm4.decrypt(encryptData, key, {padding: 'none', output: 'array'}) // 解密，不使用 padding，输出为字节数组
let decryptData = sm4.decrypt(encryptData, key, {mode: 'cbc', iv: 'fedcba98765432100123456789abcdef'}) // 解密，cbc 模式
```

## 其他实现

* 小程序移植版：[https://github.com/wechat-miniprogram/sm-crypto](https://github.com/wechat-miniprogram/sm-crypto)
* java 实现（感谢 @antherd 提供）：[https://github.com/antherd/sm-crypto](https://github.com/antherd/sm-crypto)
* dart 实现（感谢 @luckykellan 提供）：[https://github.com/luckykellan/dart_sm](https://github.com/luckykellan/dart_sm)
## 协议

MIT
