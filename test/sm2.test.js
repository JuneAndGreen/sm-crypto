const sm2 = require('../src/index').sm2

const cipherMode = 1 // 1 - C1C3C2，0 - C1C2C3

// const msgString = 'abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH';
const msgString = 'absasdagfadgadsfdfdsf'

let unCompressedPublicKey
let compressedPublicKey
let privateKey

beforeAll(() => {
  // 生成密钥对
  const keypair = sm2.generateKeyPairHex()

  unCompressedPublicKey = keypair.publicKey
  privateKey = keypair.privateKey

  compressedPublicKey = sm2.compressPublicKeyHex(unCompressedPublicKey)
})

test('sm2: generate keypair', () => {
  expect(unCompressedPublicKey.length).toBe(130)
  expect(privateKey.length).toBe(64)
  expect(compressedPublicKey.length).toBe(66)
  expect(sm2.verifyPublicKey(unCompressedPublicKey)).toBe(true)
  expect(sm2.verifyPublicKey(compressedPublicKey)).toBe(true)
  expect(sm2.comparePublicKeyHex(unCompressedPublicKey, compressedPublicKey)).toBe(true)
  expect(sm2.comparePublicKeyHex(unCompressedPublicKey, unCompressedPublicKey)).toBe(true)
  expect(sm2.comparePublicKeyHex(compressedPublicKey, compressedPublicKey)).toBe(true)

  // 自定义随机数
  const random = []
  for (let i = 0; i < 20; i++) random.push(~~(Math.random() * 10))
  const keypair2 = sm2.generateKeyPairHex(random.join(''))
  expect(keypair2.publicKey.length).toBe(130)
  expect(keypair2.privateKey.length).toBe(64)
  const compressedPublicKey2 = sm2.compressPublicKeyHex(keypair2.publicKey)
  expect(compressedPublicKey2.length).toBe(66)
  expect(sm2.verifyPublicKey(keypair2.publicKey)).toBe(true)
  expect(sm2.verifyPublicKey(compressedPublicKey2)).toBe(true)
  expect(sm2.comparePublicKeyHex(keypair2.publicKey, compressedPublicKey2)).toBe(true)
})

test('sm2: encrypt and decrypt data', () => {
  for (const publicKey of [unCompressedPublicKey, compressedPublicKey]) {
    let encryptData = sm2.doEncrypt(msgString, publicKey, cipherMode)
    let decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode)
    expect(decryptData).toBe(msgString)

    for (let i = 0; i < 100; i++) {
      encryptData = sm2.doEncrypt(msgString, publicKey, cipherMode)
      decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode)
      expect(decryptData).toBe(msgString)
    }

    encryptData = sm2.doEncrypt([0x61, 0x62, 0x73, 0x61, 0x73, 0x64, 0x61, 0x67, 0x66, 0x61, 0x64, 0x67, 0x61, 0x64, 0x73, 0x66, 0x64, 0x66, 0x64, 0x73, 0x66], publicKey, cipherMode)
    decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode)
    expect(decryptData).toBe(msgString)
    encryptData = sm2.doEncrypt(Uint8Array.from([0x61, 0x62, 0x73, 0x61, 0x73, 0x64, 0x61, 0x67, 0x66, 0x61, 0x64, 0x67, 0x61, 0x64, 0x73, 0x66, 0x64, 0x66, 0x64, 0x73, 0x66]), publicKey, cipherMode)
    decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode)
    expect(decryptData).toBe(msgString)
    decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode, {output: 'array'})
    expect(decryptData).toEqual([0x61, 0x62, 0x73, 0x61, 0x73, 0x64, 0x61, 0x67, 0x66, 0x61, 0x64, 0x67, 0x61, 0x64, 0x73, 0x66, 0x64, 0x66, 0x64, 0x73, 0x66])
  }
})

test('sm2: sign data and verify sign', () => {
  for (const publicKey of [unCompressedPublicKey, compressedPublicKey]) {
    // 纯签名 + 生成椭圆曲线点
    const sigValueHex = sm2.doSignature(msgString, privateKey, {
      hash: false,
    })
    const verifyResult = sm2.doVerifySignature(msgString, sigValueHex, publicKey, {
      hash: false,
    })
    expect(verifyResult).toBe(true)

    // 纯签名
    const sigValueHex2 = sm2.doSignature(msgString, privateKey, {
      hash: false,
      pointPool: [sm2.getPoint(), sm2.getPoint(), sm2.getPoint(), sm2.getPoint()],
    })
    const verifyResult2 = sm2.doVerifySignature(msgString, sigValueHex2, publicKey, {
      hash: false,
    })
    expect(verifyResult2).toBe(true)

    // 纯签名 + 生成椭圆曲线点 + der编解码
    const sigValueHex3 = sm2.doSignature(msgString, privateKey, {
      der: true,
      hash: false,
    })
    const verifyResult3 = sm2.doVerifySignature(msgString, sigValueHex3, publicKey, {
      der: true,
      hash: false,
    })
    expect(verifyResult3).toBe(true)

    // 纯签名 + 生成椭圆曲线点 + sm3杂凑
    let sigValueHex4 = sm2.doSignature(msgString, privateKey)
    let verifyResult4 = sm2.doVerifySignature(msgString, sigValueHex4, publicKey)
    expect(verifyResult4).toBe(true)
    verifyResult4 = sm2.doVerifySignature(msgString, sigValueHex4, publicKey, {
      hash: true,
    })
    expect(verifyResult4).toBe(true)

    for (let i = 0; i < 100; i++) {
      sigValueHex4 = sm2.doSignature(msgString, privateKey)
      verifyResult4 = sm2.doVerifySignature(msgString, sigValueHex4, publicKey)
      expect(verifyResult4).toBe(true)
    }

    // 纯签名 + 生成椭圆曲线点 + sm3杂凑（不做公钥推导）
    const sigValueHex5 = sm2.doSignature(msgString, privateKey, {
      publicKey,
    })
    const verifyResult5 = sm2.doVerifySignature(msgString, sigValueHex5, publicKey, {
      publicKey,
    })
    expect(verifyResult5).toBe(true)

    // 纯签名 + 生成椭圆曲线点 + sm3杂凑 + 不做公钥推 + 添加 userId
    let sigValueHex6 = sm2.doSignature(msgString, privateKey, {
      publicKey,
      userId: 'testUserId',
    })
    let verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
      userId: 'testUserId',
    })
    expect(verifyResult6).toBe(true)
    verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
      userId: 'wrongTestUserId',
    })
    expect(verifyResult6).toBe(false)
    sigValueHex6 = sm2.doSignature(msgString, privateKey, {
      publicKey,
      userId: '',
    })
    verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
      userId: '',
    })
    expect(verifyResult6).toBe(true)
    verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey)
    expect(verifyResult6).toBe(false)
    sigValueHex6 = sm2.doSignature(msgString, privateKey, {
      publicKey,
    })
    verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey)
    expect(verifyResult6).toBe(true)
    verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
      userId: '',
    })
    expect(verifyResult6).toBe(false)
    verifyResult6 = sm2.doVerifySignature(msgString, sigValueHex6, publicKey, {
      userId: '1234567812345678'
    })
    expect(verifyResult6).toBe(true)
  }
})

test('sm2: getPublicKeyFromPrivateKey', () => {
  for (let i = 0; i < 10; i++) {
    const {privateKey, publicKey} = sm2.generateKeyPairHex()
    expect(sm2.getPublicKeyFromPrivateKey(privateKey)).toEqual(publicKey)
  }
})

test('sm2: decrypt with invalid c1 point', () => {
  const encryptData = sm2.doEncrypt(msgString, unCompressedPublicKey, cipherMode)
  const invalidC1 = '00'.repeat(64)
  const invalidEncryptData = invalidC1 + encryptData.substr(128)
  const decryptData = sm2.doDecrypt(invalidEncryptData, privateKey, cipherMode)
  expect(decryptData).toBe('')
})

test('sm2: verify signature with invalid r or s', () => {
  const invalidSigHexZeroR = '00'.repeat(32) + 'a'.repeat(64)
  let verifyResult = sm2.doVerifySignature(msgString, invalidSigHexZeroR, unCompressedPublicKey)
  expect(verifyResult).toBe(false)
  // invalid, should be in [1, n-1]
  const invalidSigHexZeroS = 'a'.repeat(64) + '00'.repeat(32)
  verifyResult = sm2.doVerifySignature(msgString, invalidSigHexZeroS, unCompressedPublicKey)
  expect(verifyResult).toBe(false)
  const sigValueHex = sm2.doSignature(msgString, privateKey)
  verifyResult = sm2.doVerifySignature(msgString, sigValueHex, unCompressedPublicKey)
  expect(verifyResult).toBe(true)
})

test('sm2: verify signature with invalid public key', () => {
  const sigValueHex = sm2.doSignature(msgString, privateKey)
  // invalid
  const invalidPublicKey = '04' + '00'.repeat(64)
  let verifyResult = sm2.doVerifySignature(msgString, sigValueHex, invalidPublicKey)
  expect(verifyResult).toBe(false)
  // invalid
  const invalidPublicKey2 = '04' + 'a'.repeat(10)
  verifyResult = sm2.doVerifySignature(msgString, sigValueHex, invalidPublicKey2)
  expect(verifyResult).toBe(false)
  verifyResult = sm2.doVerifySignature(msgString, sigValueHex, unCompressedPublicKey)
  expect(verifyResult).toBe(true)
  verifyResult = sm2.doVerifySignature(msgString, sigValueHex, compressedPublicKey)
  expect(verifyResult).toBe(true)
})
