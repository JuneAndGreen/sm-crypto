/* eslint-disable no-use-before-define */
const {BigInteger} = require('jsbn')
const {encodeDer, decodeDer} = require('./asn1')
const SM3Digest = require('./sm3')
const SM2Cipher = require('./sm2')
const _ = require('./utils')

const {G, curve, n} = _.generateEcparam()
const C1C2C3 = 0

/**
 * 加密
 */
function doEncrypt(msg, publicKey, cipherMode = 1) {
  const cipher = new SM2Cipher()
  msg = _.hexToArray(_.parseUtf8StringToHex(msg))

  if (publicKey.length > 128) {
    publicKey = publicKey.substr(publicKey.length - 128)
  }
  const xHex = publicKey.substr(0, 64)
  const yHex = publicKey.substr(64)
  publicKey = cipher.createPoint(xHex, yHex)

  const c1 = cipher.initEncipher(publicKey)

  cipher.encryptBlock(msg)
  const c2 = _.arrayToHex(msg)

  let c3 = new Array(32)
  cipher.doFinal(c3)
  c3 = _.arrayToHex(c3)

  return cipherMode === C1C2C3 ? c1 + c2 + c3 : c1 + c3 + c2
}

/**
 * 解密
 */
function doDecrypt(encryptData, privateKey, cipherMode = 1) {
  const cipher = new SM2Cipher()

  privateKey = new BigInteger(privateKey, 16)

  const c1X = encryptData.substr(0, 64)
  const c1Y = encryptData.substr(0 + c1X.length, 64)
  const c1Length = c1X.length + c1Y.length

  let c3 = encryptData.substr(c1Length, 64)
  let c2 = encryptData.substr(c1Length + 64)

  if (cipherMode === C1C2C3) {
    c3 = encryptData.substr(encryptData.length - 64)
    c2 = encryptData.substr(c1Length, encryptData.length - c1Length - 64)
  }

  const data = _.hexToArray(c2)

  const c1 = cipher.createPoint(c1X, c1Y)
  cipher.initDecipher(privateKey, c1)
  cipher.decryptBlock(data)
  const c3_ = new Array(32)
  cipher.doFinal(c3_)

  const isDecrypt = _.arrayToHex(c3_) === c3

  if (isDecrypt) {
    const decryptData = _.arrayToUtf8(data)
    return decryptData
  } else {
    return ''
  }
}

/**
 * 签名
 */
function doSignature(msg, privateKey, {
  pointPool, der, hash, publicKey
} = {}) {
  let hashHex = typeof msg === 'string' ? _.parseUtf8StringToHex(msg) : _.parseArrayBufferToHex(msg)

  if (hash) {
    // sm3杂凑
    publicKey = publicKey || getPublicKeyFromPrivateKey(privateKey)
    hashHex = doSm3Hash(hashHex, publicKey)
  }

  const dA = new BigInteger(privateKey, 16)
  const e = new BigInteger(hashHex, 16)

  // k
  let k = null
  let r = null
  let s = null

  do {
    do {
      let point
      if (pointPool && pointPool.length) {
        point = pointPool.pop()
      } else {
        point = getPoint()
      }
      k = point.k

      // r = (e + x1) mod n
      r = e.add(point.x1).mod(n)
    } while (r.equals(BigInteger.ZERO) || r.add(k).equals(n))

    // s = ((1 + dA)^-1 * (k - r * dA)) mod n
    s = dA.add(BigInteger.ONE).modInverse(n).multiply(k.subtract(r.multiply(dA))).mod(n)
  } while (s.equals(BigInteger.ZERO))

  if (der) {
    // asn1 der编码
    return encodeDer(r, s)
  }

  return _.leftPad(r.toString(16), 64) + _.leftPad(s.toString(16), 64)
}

/**
 * 验签
 */
function doVerifySignature(msg, signHex, publicKey, {der, hash} = {}) {
  let hashHex = typeof msg === 'string' ? _.parseUtf8StringToHex(msg) : _.parseArrayBufferToHex(msg)

  if (hash) {
    // sm3杂凑
    hashHex = doSm3Hash(hashHex, publicKey)
  }

  let r; let
    s
  if (der) {
    const decodeDerObj = decodeDer(signHex)
    r = decodeDerObj.r
    s = decodeDerObj.s
  } else {
    r = new BigInteger(signHex.substring(0, 64), 16)
    s = new BigInteger(signHex.substring(64), 16)
  }

  const PA = curve.decodePointHex(publicKey)
  const e = new BigInteger(hashHex, 16)

  // t = (r + s) mod n
  const t = r.add(s).mod(n)

  if (t.equals(BigInteger.ZERO)) return false

  // x1y1 = s * G + t * PA
  const x1y1 = G.multiply(s).add(PA.multiply(t))

  // R = (e + x1) mod n
  const R = e.add(x1y1.getX().toBigInteger()).mod(n)

  return r.equals(R)
}

/**
 * sm3杂凑算法
 */
function doSm3Hash(hashHex, publicKey) {
  const smDigest = new SM3Digest()

  const z = new SM3Digest().getZ(G, publicKey.substr(2, 128))
  const zValue = _.hexToArray(_.arrayToHex(z).toString())

  const p = hashHex
  const pValue = _.hexToArray(p)

  const hashData = new Array(smDigest.getDigestSize())
  smDigest.blockUpdate(zValue, 0, zValue.length)
  smDigest.blockUpdate(pValue, 0, pValue.length)
  smDigest.doFinal(hashData, 0)

  return _.arrayToHex(hashData).toString()
}

/**
 * 计算公钥
 */
function getPublicKeyFromPrivateKey(privateKey) {
  const PA = G.multiply(new BigInteger(privateKey, 16))
  const x = _.leftPad(PA.getX().toBigInteger().toString(16), 64)
  const y = _.leftPad(PA.getY().toBigInteger().toString(16), 64)
  return '04' + x + y
}

/**
 * 获取椭圆曲线点
 */
function getPoint() {
  const keypair = _.generateKeyPairHex()
  const PA = curve.decodePointHex(keypair.publicKey)

  keypair.k = new BigInteger(keypair.privateKey, 16)
  keypair.x1 = PA.getX().toBigInteger()

  return keypair
}

module.exports = {
  generateKeyPairHex: _.generateKeyPairHex,
  doEncrypt,
  doDecrypt,
  doSignature,
  doVerifySignature,
  getPoint,
}
