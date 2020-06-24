/* eslint-disable no-bitwise, no-mixed-operators, class-methods-use-this */
const {BigInteger} = require('jsbn')
const SM3Digest = require('./sm3')
const _ = require('./utils')

class SM2Cipher {
  constructor() {
    this.ct = 1
    this.p2 = null
    this.sm3keybase = null
    this.sm3c3 = null
    this.key = new Array(32)
    this.keyOff = 0
  }

  reset() {
    this.sm3keybase = new SM3Digest()
    this.sm3c3 = new SM3Digest()
    const xWords = _.hexToArray(this.p2.getX().toBigInteger().toRadix(16))
    const yWords = _.hexToArray(this.p2.getY().toBigInteger().toRadix(16))
    this.sm3keybase.blockUpdate(xWords, 0, xWords.length)
    this.sm3c3.blockUpdate(xWords, 0, xWords.length)
    this.sm3keybase.blockUpdate(yWords, 0, yWords.length)
    this.ct = 1
    this.nextKey()
  }

  nextKey() {
    const sm3keycur = new SM3Digest(this.sm3keybase)
    sm3keycur.update((this.ct >> 24 & 0x00ff))
    sm3keycur.update((this.ct >> 16 & 0x00ff))
    sm3keycur.update((this.ct >> 8 & 0x00ff))
    sm3keycur.update((this.ct & 0x00ff))
    sm3keycur.doFinal(this.key, 0)
    this.keyOff = 0
    this.ct++
  }

  initEncipher(userKey) {
    const keypair = _.generateKeyPairHex()
    const k = new BigInteger(keypair.privateKey, 16)
    let publicKey = keypair.publicKey

    this.p2 = userKey.multiply(k) // [k](Pb)
    this.reset()

    if (publicKey.length > 128) {
      publicKey = publicKey.substr(publicKey.length - 128)
    }

    return publicKey
  }

  encryptBlock(data) {
    this.sm3c3.blockUpdate(data, 0, data.length)
    for (let i = 0; i < data.length; i++) {
      if (this.keyOff === this.key.length) {
        this.nextKey()
      }
      data[i] ^= this.key[this.keyOff++] & 0xff
    }
  }

  initDecipher(userD, c1) {
    this.p2 = c1.multiply(userD)
    this.reset()
  }

  decryptBlock(data) {
    for (let i = 0; i < data.length; i++) {
      if (this.keyOff === this.key.length) {
        this.nextKey()
      }
      data[i] ^= this.key[this.keyOff++] & 0xff
    }
    this.sm3c3.blockUpdate(data, 0, data.length)
  }

  doFinal(c3) {
    const yWords = _.hexToArray(this.p2.getY().toBigInteger().toRadix(16))
    this.sm3c3.blockUpdate(yWords, 0, yWords.length)
    this.sm3c3.doFinal(c3, 0)
    this.reset()
  }

  createPoint(x, y) {
    const publicKey = '04' + x + y
    const point = _.getGlobalCurve().decodePointHex(publicKey)
    return point
  }
}

module.exports = SM2Cipher
