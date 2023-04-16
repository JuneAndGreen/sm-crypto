// 主要参考 GM/T 0091—2020  基于口令的派生密钥规范实现
const {hmac} = require('../sm2/sm3')

/**
 * 数字转
 * @param value
 * @returns {number[]}
 */
function intTobyte(value) {
  const src = [4]
  src[0] = (value >> 24 & 0xFF)
  src[1] = (value >> 16 & 0xFF)
  src[2] = (value >> 8 & 0xFF)
  src[3] = (value & 0xFF)
  return src
}

function xor(x, y) {
  const result = []
  for (let i = x.length - 1; i >= 0; i--) result[i] = (x[i] ^ y[i]) & 0xff
  return result
}


function PRF2(p, s, i) {
  const iArray = intTobyte(i)
  const hash = hmac(s.concat(iArray), p)
  return hash
}

function PRF(p, s) {
  const hash = hmac(s, p)
  return hash
}
function F(p, s, c, i) {
  let U = []
  const U1 = PRF2(p, s, i)
  let Uxor = U1
  U = U1
  for (let x = 0; x < c - 1; x++) {
    const Ux = PRF(p, U)
    U = Ux
    Uxor = xor(Uxor, Ux)
  }
  return Uxor
}

function pbkdf2SM3(password, salt, c, dkLen) {
  const hLen = 32

  if (dkLen < hLen) {
    const t1 = F(password, salt, c, 1)
    const dk = t1.slice(0, dkLen)
    return dk
  } else {
    const block = dkLen / hLen
    const r = dkLen % hLen

    let dk = []

    for (let i = 1; i < block + 1; i++) {
      const ti = F(password, salt, c, i)
      dk = dk.concat(ti)
    }
    const tLast = F(password, salt, c, block + 1)
    const tLastRemaining = tLast.slice(0, r)

    dk = dk.concat(tLastRemaining)
    return dk
  }
}


module.exports = {
  pbkdf2: pbkdf2SM3,
}
