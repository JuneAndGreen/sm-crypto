const sm3 = require('../sm2/sm3')

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
 * 16 进制串转字节数组
 */
function hexToArray(str) {
  const arr = []
  for (let i = 0, len = str.length; i < len; i += 2) {
    arr.push(parseInt(str.substr(i, 2), 16))
  }
  return arr
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

/**
 * 二进制异或运算
 */
function xor(x, y) {
  const result = []
  for (let i = x.length - 1; i >= 0; i--) result[i] = (x[i] ^ y[i]) & 0xff
  return result
}

module.exports = function (input,sm3_key) {
  let BLOCK_LENGTH=64;
  let structured_key=new Array(BLOCK_LENGTH);

  let IPAD=new Array(BLOCK_LENGTH);
  let OPAD=new Array(BLOCK_LENGTH);

  input = typeof input === 'string' ? utf8ToArray(input) : Array.prototype.slice.call(input)
  sm3_key = typeof sm3_key === 'string' ? utf8ToArray(sm3_key) : Array.prototype.slice.call(sm3_key)

  //1 密钥填充
  if (sm3_key.length>BLOCK_LENGTH){
      sm3_key=sm3(sm3_key);
      for (let i = 0; i < sm3_key.length; i++) {
        structured_key[i]=sm3_key[i];
      }
  }else {
    for (let i = 0; i < sm3_key.length; i++) {
      structured_key[i]=sm3_key[i];
    }
  }
  //2 与ipad异或运算
  for (let i = 0; i < BLOCK_LENGTH; i++) {
      IPAD[i]=0x36;
      OPAD[i]=0x5c;
  }
  let ipadkey=xor(structured_key,IPAD);
  //3  拼接组合
  let ipadkey_message=ipadkey.concat(input);
  //4  计算散列值
  let hash1=sm3(ipadkey_message);


  //5 与opad异或运算
  let opadkey=xor(structured_key,OPAD);
  //6 hash1结合
  let opadkey_hash1=opadkey.concat(hash1);
  //7 计算散列值
  let hash2=sm3(opadkey_hash1);
  return ArrayToHex(hash2)
}
