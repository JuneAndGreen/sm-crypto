/* eslint-disable class-methods-use-this */
const {BigInteger} = require('jsbn')

function bigintToValue(bigint) {
  let h = bigint.toString(16)
  if (h[0] !== '-') {
    // 正数
    if (h.length % 2 === 1) h = '0' + h // 补齐到整字节
    else if (!h.match(/^[0-7]/)) h = '00' + h // 非0开头，则补一个全0字节
  } else {
    // 负数
    h = h.substr(1)

    let len = h.length
    if (len % 2 === 1) len += 1 // 补齐到整字节
    else if (!h.match(/^[0-7]/)) len += 2 // 非0开头，则补一个全0字节

    let mask = ''
    for (let i = 0; i < len; i++) mask += 'f'
    mask = new BigInteger(mask, 16)

    // 对绝对值取反，加1
    h = mask.xor(bigint).add(BigInteger.ONE)
    h = h.toString(16).replace(/^-/, '')
  }
  return h
}

class ASN1Object {
  constructor() {
    this.tlv = null
    this.t = '00'
    this.l = '00'
    this.v = ''
  }

  /**
   * 获取 der 编码比特流16进制串
   */
  getEncodedHex() {
    if (!this.tlv) {
      this.v = this.getValue()
      this.l = this.getLength()
      this.tlv = this.t + this.l + this.v
    }
    return this.tlv
  }

  getLength() {
    const n = this.v.length / 2 // 字节数
    let nHex = n.toString(16)
    if (nHex.length % 2 === 1) nHex = '0' + nHex // 补齐到整字节

    if (n < 128) {
      // 短格式，以 0 开头
      return nHex
    } else {
      // 长格式，以 1 开头
      const head = 128 + nHex.length / 2 // 1(1位) + 真正的长度占用字节数(7位) + 真正的长度
      return head.toString(16) + nHex
    }
  }

  getValue() {
    return ''
  }
}

class DERInteger extends ASN1Object {
  constructor(bigint) {
    super()

    this.t = '02' // 整型标签说明
    if (bigint) this.v = bigintToValue(bigint)
  }

  getValue() {
    return this.v
  }
}

class DERSequence extends ASN1Object {
  constructor(asn1Array) {
    super()

    this.t = '30' // 序列标签说明
    this.asn1Array = asn1Array
  }

  getValue() {
    this.v = this.asn1Array.map(asn1Object => asn1Object.getEncodedHex()).join('')
    return this.v
  }
}

/**
 * 解析 TLV 中的 length 字段
 * 严格校验 DER 规范：
 * - 短格式（首字节 < 0x80）：长度直接由首字节表示
 * - 长格式（首字节 >= 0x80）：低 7 位为后续长度字节数
 *   - 长度字节数必须最小（不能有前导 0）
 *   - 长度值 < 128 必须用短格式
 * 返回 { len, lenOfL }，len 为 value 的字节数，lenOfL 为 length 字段占用的字节数
 * 校验失败抛出 Error
 */
function parseLength(str, start) {
  if (start + 2 > str.length) throw new Error('invalid DER: length field truncated')
  const first = parseInt(str.substring(start, start + 2), 16)
  if (first < 0x80) {
    // 短格式
    return {len: first, lenOfL: 1}
  }
  // 长格式
  const numBytes = first & 0x7f
  if (numBytes === 0) throw new Error('invalid DER: indefinite length not allowed')
  if (numBytes > 4) throw new Error('invalid DER: length too large')
  if (start + 2 + numBytes * 2 > str.length) throw new Error('invalid DER: length field truncated')
  const lenHex = str.substring(start + 2, start + 2 + numBytes * 2)
  const len = parseInt(lenHex, 16)
  // 长度值 < 128 必须用短格式
  if (len < 0x80) throw new Error('invalid DER: length not minimally encoded (should use short form)')
  // 长度字节不能有前导 0
  if (lenHex.substring(0, 2) === '00') throw new Error('invalid DER: length has leading zero byte')
  return {len, lenOfL: 1 + numBytes}
}

/**
 * 解析一个 TLV，返回 { tag, valueHex, nextStart }
 * 严格校验 DER 规范
 */
function parseTLV(str, start) {
  if (start + 2 > str.length) throw new Error('invalid DER: tag field truncated')
  const tag = str.substring(start, start + 2)
  const {len, lenOfL} = parseLength(str, start + 2)
  const valueStart = start + 2 + lenOfL * 2
  const valueEnd = valueStart + len * 2
  if (valueEnd > str.length) throw new Error('invalid DER: value truncated')
  return {
    tag,
    valueHex: str.substring(valueStart, valueEnd),
    nextStart: valueEnd,
  }
}

/**
 * 校验 DER INTEGER 的 value 是否为最小编码
 * - 不能为空
 * - 若首字节为 0x00，则次字节的最高位必须为 1（否则前导 0 是多余的）
 * - 不能是负数（首字节最高位不能为 1，因为签名中的 r/s 是正整数）
 */
function assertMinimalInteger(valueHex) {
  if (valueHex.length === 0) throw new Error('invalid DER: INTEGER is empty')
  const firstByte = parseInt(valueHex.substring(0, 2), 16)
  if (firstByte & 0x80) throw new Error('invalid DER: INTEGER is negative')
  if (firstByte === 0x00) {
    if (valueHex.length === 2) {
      // 只有一个字节 0x00，表示 0，合法（但对签名而言 r/s 不能为 0，由上层范围检查处理）
      return
    }
    const secondByte = parseInt(valueHex.substring(2, 4), 16)
    if (!(secondByte & 0x80)) throw new Error('invalid DER: INTEGER has non-minimal leading zero')
  }
}

module.exports = {
  /**
   * ASN.1 der 编码，针对 sm2 签名
   */
  encodeDer(r, s) {
    const derR = new DERInteger(r)
    const derS = new DERInteger(s)
    const derSeq = new DERSequence([derR, derS])

    return derSeq.getEncodedHex()
  },

  /**
   * 解析 ASN.1 der，针对 sm2 验签
   * 严格校验规范 DER 编码，拒绝任何非规范编码（例如：
   * INTEGER 前导 00 填充、外层 SEQUENCE 长度与实际不符、错误的 tag 等），
   * 以避免签名可延展性（signature malleability）问题。
   */
  decodeDer(input) {
    if (typeof input !== 'string' || input.length % 2 !== 0) {
      throw new Error('invalid DER: input must be a hex string of even length')
    }

    // 外层 SEQUENCE
    if (input.substring(0, 2) !== '30') throw new Error('invalid DER: expected SEQUENCE (0x30)')
    const seqLenInfo = parseLength(input, 2)
    const seqValueOffset = 2 + seqLenInfo.lenOfL * 2
    // 外层 SEQUENCE 长度必须与剩余输入完全一致（禁止尾部多余字节 / 长度不一致）
    if (seqValueOffset + seqLenInfo.len * 2 !== input.length) {
      throw new Error('invalid DER: SEQUENCE length does not match input length')
    }

    // 内部第一个 INTEGER: R
    const rParsed = parseTLV(input, seqValueOffset)
    if (rParsed.tag !== '02') throw new Error('invalid DER: expected INTEGER (0x02) for R')
    assertMinimalInteger(rParsed.valueHex)

    const sParsed = parseTLV(input, rParsed.nextStart)
    if (sParsed.tag !== '02') throw new Error('invalid DER: expected INTEGER (0x02) for S')
    assertMinimalInteger(sParsed.valueHex)

    // S 必须刚好到 SEQUENCE 末尾
    if (sParsed.nextStart !== input.length) throw new Error('invalid DER: trailing bytes inside SEQUENCE')

    const r = new BigInteger(rParsed.valueHex, 16)
    const s = new BigInteger(sParsed.valueHex, 16)

    return {r, s}
  }
}
