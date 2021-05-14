/**
 * 循环左移
 */
function rotl(x, n) {
  const result = []
  const a = ~~(n / 8) // 偏移 a 字节
  const b = n % 8 // 偏移 b 位
  for (let i = 0, len = x.length; i < len; i++) {
    // current << b + (current + 1) >>> (8 - b)
    result[i] = ((x[(i + a) % len] << b) & 0xff) + ((x[(i + a + 1) % len] >>> (8 - b)) & 0xff)
  }
  return result
}

/**
 * 二进制异或运算
 */
function xor(x, y) {
  const result = []
  for (let i = x.length - 1; i >= 0; i--) result[i] = (x[i] ^ y[i]) & 0xff
  return result
}

/**
 * 二进制与运算
 */
function and(x, y) {
  const result = []
  for (let i = x.length - 1; i >= 0; i--) result[i] = (x[i] & y[i]) & 0xff
  return result
}

/**
 * 二进制或运算
 */
function or(x, y) {
  const result = []
  for (let i = x.length - 1; i >= 0; i--) result[i] = (x[i] | y[i]) & 0xff
  return result
}

/**
 * 二进制与运算
 */
function add(x, y) {
  const result = []
  let temp = 0
  for (let i = x.length - 1; i >= 0; i--) {
    const sum = x[i] + y[i] + temp
    if (sum > 0xff) {
      temp = 1
      result[i] = sum & 0xff
    } else {
      temp = 0
      result[i] = sum & 0xff
    }
  }
  return result
}

/**
 * 二进制非运算
 */
function not(x) {
  const result = []
  for (let i = x.length - 1; i >= 0; i--) result[i] = (~x[i]) & 0xff
  return result
}

/**
 * 压缩函数中的置换函数 P1(X) = X xor (X <<< 9) xor (X <<< 17)
 */
function P0(X) {
  return xor(xor(X, rotl(X, 9)), rotl(X, 17))
}

/**
 * 消息扩展中的置换函数 P1(X) = X xor (X <<< 15) xor (X <<< 23)
 */
function P1(X) {
  return xor(xor(X, rotl(X, 15)), rotl(X, 23))
}

/**
 * 布尔函数 FF
 */
function FF(X, Y, Z, j) {
  return j >= 0 && j <= 15 ? xor(xor(X, Y), Z) : or(or(and(X, Y), and(X, Z)), and(Y, Z))
}

/**
 * 布尔函数 GG
 */
function GG(X, Y, Z, j) {
  return j >= 0 && j <= 15 ? xor(xor(X, Y), Z) : or(and(X, Y), and(not(X), Z))
}

/**
 * 压缩函数
 */
function CF(V, Bi) {
  // 消息扩展
  const W = []
  const M = [] // W'

  // 将消息分组B划分为 16 个字 W0， W1，……，W15
  for (let i = 0; i < 16; i++) {
    const start = i * 4
    W.push(Bi.slice(start, start + 4))
  }

  // W16 ～ W67：W[j] <- P1(W[j−16] xor W[j−9] xor (W[j−3] <<< 15)) xor (W[j−13] <<< 7) xor W[j−6]
  for (let j = 16; j < 68; j++) {
    W.push(xor(
      xor(
        P1(
          xor(
            xor(W[j - 16], W[j - 9]),
            rotl(W[j - 3], 15)
          )
        ),
        rotl(W[j - 13], 7)
      ),
      W[j - 6]
    ))
  }

  // W′0 ～ W′63：W′[j] = W[j] xor W[j+4]
  for (let j = 0; j < 64; j++) {
    M.push(xor(W[j], W[j + 4]))
  }

  // 压缩
  const T1 = [0x79, 0xcc, 0x45, 0x19]
  const T2 = [0x7a, 0x87, 0x9d, 0x8a]
  // 字寄存器
  let A = V.slice(0, 4)
  let B = V.slice(4, 8)
  let C = V.slice(8, 12)
  let D = V.slice(12, 16)
  let E = V.slice(16, 20)
  let F = V.slice(20, 24)
  let G = V.slice(24, 28)
  let H = V.slice(28, 32)
  // 中间变量
  let SS1
  let SS2
  let TT1
  let TT2
  for (let j = 0; j < 64; j++) {
    const T = j >= 0 && j <= 15 ? T1 : T2
    SS1 = rotl(add(
      add(rotl(A, 12), E),
      rotl(T, j)
    ), 7)
    SS2 = xor(SS1, rotl(A, 12))

    TT1 = add(add(add(FF(A, B, C, j), D), SS2), M[j])
    TT2 = add(add(add(GG(E, F, G, j), H), SS1), W[j])

    D = C
    C = rotl(B, 9)
    B = A
    A = TT1
    H = G
    G = rotl(F, 19)
    F = E
    E = P0(TT2)
  }

  return xor([].concat(A, B, C, D, E, F, G, H), V)
}

module.exports = function (array) {
  // 填充
  let len = array.length * 8

  // k 是满足 len + 1 + k = 448mod512 的最小的非负整数
  let k = len % 512
  // 如果 448 <= (512 % len) < 512，需要多补充 (len % 448) 比特'0'以满足总比特长度为512的倍数
  k = k >= 448 ? 512 - (k % 448) - 1 : 448 - k - 1

  // 填充
  const kArr = new Array((k - 7) / 8)
  for (let i = 0, len = kArr.length; i < len; i++) kArr[i] = 0
  const lenArr = []
  len = len.toString(2)
  for (let i = 7; i >= 0; i--) {
    if (len.length > 8) {
      const start = len.length - 8
      lenArr[i] = parseInt(len.substr(start), 2)
      len = len.substr(0, start)
    } else if (len.length > 0) {
      lenArr[i] = parseInt(len, 2)
      len = ''
    } else {
      lenArr[i] = 0
    }
  }
  const m = [].concat(array, [0x80], kArr, lenArr)

  // 迭代压缩
  const n = m.length / 64
  let V = [0x73, 0x80, 0x16, 0x6f, 0x49, 0x14, 0xb2, 0xb9, 0x17, 0x24, 0x42, 0xd7, 0xda, 0x8a, 0x06, 0x00, 0xa9, 0x6f, 0x30, 0xbc, 0x16, 0x31, 0x38, 0xaa, 0xe3, 0x8d, 0xee, 0x4d, 0xb0, 0xfb, 0x0e, 0x4e]
  for (let i = 0; i < n; i++) {
    const start = 64 * i
    const B = m.slice(start, start + 64)
    V = CF(V, B)
  }
  return V
}
