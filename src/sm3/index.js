const {sm3, hmac, hkdf} = require('../sm2/sm3')
const {pbkdf2} = require('./pbkdf2')

/**
 * 补全16进制字符串
 */
function leftPad(input, num) {
  if (input.length >= num) return input

  return (new Array(num - input.length + 1)).join('0') + input
}

/**
 * 字节数组转 16 进制串
 */
function ArrayToHex(arr) {
  return arr.map(item => {
    item = item.toString(16)
    return item.length === 1 ? '0' + item : item
  }).join('')
}

/**
 * 转成字节数组
 */
function hexToArray(hexStr) {
  const words = []
  let hexStrLength = hexStr.length

  if (hexStrLength % 2 !== 0) {
    hexStr = leftPad(hexStr, hexStrLength + 1)
  }

  hexStrLength = hexStr.length

  for (let i = 0; i < hexStrLength; i += 2) {
    words.push(parseInt(hexStr.substr(i, 2), 16))
  }
  return words
}

/**
 * utf8 串转字节数组
 */
function utf8ToArray(str) {
  const arr = []

  for (let i = 0, len = str.length; i < len; i++) {
    const point = str.codePointAt(i)

    if (point <= 0x007f) {
      // 单字节，标量值：00000000 00000000 0zzzzzzz
      arr.push(point)
    } else if (point <= 0x07ff) {
      // 双字节，标量值：00000000 00000yyy yyzzzzzz
      arr.push(0xc0 | (point >>> 6)) // 110yyyyy（0xc0-0xdf）
      arr.push(0x80 | (point & 0x3f)) // 10zzzzzz（0x80-0xbf）
    } else if (point <= 0xD7FF || (point >= 0xE000 && point <= 0xFFFF)) {
      // 三字节：标量值：00000000 xxxxyyyy yyzzzzzz
      arr.push(0xe0 | (point >>> 12)) // 1110xxxx（0xe0-0xef）
      arr.push(0x80 | ((point >>> 6) & 0x3f)) // 10yyyyyy（0x80-0xbf）
      arr.push(0x80 | (point & 0x3f)) // 10zzzzzz（0x80-0xbf）
    } else if (point >= 0x010000 && point <= 0x10FFFF) {
      // 四字节：标量值：000wwwxx xxxxyyyy yyzzzzzz
      i++
      arr.push((0xf0 | (point >>> 18) & 0x1c)) // 11110www（0xf0-0xf7）
      arr.push((0x80 | ((point >>> 12) & 0x3f))) // 10xxxxxx（0x80-0xbf）
      arr.push((0x80 | ((point >>> 6) & 0x3f))) // 10yyyyyy（0x80-0xbf）
      arr.push((0x80 | (point & 0x3f))) // 10zzzzzz（0x80-0xbf）
    } else {
      // 五、六字节，暂时不支持
      arr.push(point)
      throw new Error('input is not supported')
    }
  }

  return arr
}

module.exports = function (input, options) {
  input = typeof input === 'string' ? utf8ToArray(input) : Array.prototype.slice.call(input)

  if (options) {
    const mode = options.mode || 'hmac'
    if (mode === 'hmac') {
      let key = options.key
      if (!key) throw new Error('invalid key')

      key = typeof key === 'string' ? hexToArray(key) : Array.prototype.slice.call(key)
      return ArrayToHex(hmac(input, key))
    } else if (mode === 'hkdf') {
      let ikm = options.ikm
      let salt = options.salt
      let info = options.info
      const len = options.len
      ikm = typeof ikm === 'string' ? hexToArray(ikm) : Array.prototype.slice.call(ikm)
      salt = typeof salt === 'string' ? hexToArray(salt) : Array.prototype.slice.call(salt)
      info = typeof info === 'string' ? hexToArray(info) : Array.prototype.slice.call(info)
      return ArrayToHex(hkdf(ikm, salt, info, len))
    } else if (mode === 'pbkdf2') {
      let password = options.password
      let salt = options.salt
      const c = options.c
      const dkLen = options.dkLen

      password = typeof password === 'string' ? hexToArray(password) : Array.prototype.slice.call(password)
      salt = typeof salt === 'string' ? hexToArray(salt) : Array.prototype.slice.call(salt)
      return ArrayToHex(pbkdf2(password, salt, c, dkLen))
    } else {
      throw new Error('invalid mode')
    }
  }

  return ArrayToHex(sm3(input))
}
