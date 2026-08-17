/**
 * 因为 jsbn 的 SecureRandom 实现存在一些问题，故这里进行平替实现
 */
let rngState
let rngPool
let rngPptr
const rngPsize = 256

// prng4.js - uses Arcfour as a PRNG
class Arcfour {
  constructor() {
    this.i = 0
    this.j = 0
    this.S = []
  }

  // Initialize arcfour context from key, an array of ints, each from [0..255]
  init(key) {
    let i; let j; let
      t
    for (i = 0; i < 256; ++i) this.S[i] = i
    j = 0
    for (i = 0; i < 256; ++i) {
      j = (j + this.S[i] + key[i % key.length]) & 255
      t = this.S[i]
      this.S[i] = this.S[j]
      this.S[j] = t
    }
    this.i = 0
    this.j = 0
  }

  next() {
    this.i = (this.i + 1) & 255
    this.j = (this.j + this.S[this.i]) & 255
    const t = this.S[this.i]
    this.S[this.i] = this.S[this.j]
    this.S[this.j] = t
    return this.S[(t + this.S[this.i]) & 255]
  }
}

// Mix in a 32-bit integer into the pool
function rngSeedInt(x) {
  rngPool[rngPptr++] ^= x & 255
  rngPool[rngPptr++] ^= (x >> 8) & 255
  rngPool[rngPptr++] ^= (x >> 16) & 255
  rngPool[rngPptr++] ^= (x >> 24) & 255
  if (rngPptr >= rngPsize) rngPptr -= rngPsize
}

// Mix in the current time (w/milliseconds) into the pool
function rngSeedTime() {
  rngSeedInt(new Date().getTime())
}

// Initialize the pool with junk if needed.
if (rngPool == null) {
  rngPool = []
  rngPptr = 0
  let t

  const ua = new Uint8Array(32)
  if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
    // Use webcrypto if available
    window.crypto.getRandomValues(ua)
    for (t = 0; t < 32; ++t) rngPool[rngPptr++] = ua[t]
  } else {
    const nodeRequire = (typeof module !== 'undefined' && typeof module.require === 'function') ? module.require.bind(module) : null
    const nodeCrypto = nodeRequire ? nodeRequire('crypto') : null
    if (nodeCrypto) nodeCrypto.getRandomValues(ua)
    else if (globalThis.crypto) globalThis.crypto.getRandomValues(ua)
    else throw new Error('当前环境不支持 crypto.getRandomValues！')
    for (t = 0; t < 32; ++t) rngPool[rngPptr++] = ua[t]
  }

  rngPptr = 0
  rngSeedTime()
  // rngSeedInt(window.screenX);
  // rngSeedInt(window.screenY);
}

function rngGetByte() {
  if (rngState == null) {
    rngSeedTime()
    rngState = new Arcfour()
    rngState.init(rngPool)
    for (rngPptr = 0; rngPptr < rngPool.length; ++rngPptr) rngPool[rngPptr] = 0
    rngPptr = 0
    // rngPool = null;
  }
  // TODO: allow reseeding after first request
  return rngState.next()
}

class SecureRandom {
  // eslint-disable-next-line class-methods-use-this
  nextBytes(ba) {
    for (let i = 0; i < ba.length; ++i) ba[i] = rngGetByte()
  }
}

module.exports = {
  SecureRandom,
}
