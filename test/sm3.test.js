const sm3 = require('../src/index').sm3

test('sm3: must match the result', () => {
    expect(sm3('abc')).toBe('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')

    expect(sm3('abcdefghABCDEFGH12345678')).toBe('d670c7f027fd5f9f0c163f4bfe98f9003fe597d3f52dbab0885ec2ca8dd23e9b')

    expect(sm3('abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefgh')).toBe('1cf3bafec325d7d9102cd67ba46b09195af4e613b6c2b898122363d810308b11')

    expect(sm3('abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCD')).toBe('b8ac4203969bde27434ce667b0adbf3439ee97e416e73cb96f4431f478a531fe')

    expect(sm3('abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDEFGH')).toBe('5ef0cdbe0d54426eea7f5c8b44385bb1003548735feaa59137c3dfe608aa9567')
    
    expect(sm3('abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd')).toBe('debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')

    // 中文
    expect(sm3('今天天气真是不错')).toBe('fff6e05118c782f5a2cea8bc2efec8819d0dc6d7d09cb9aa5c4ef14e673fa043')
    expect(sm3('今天天气真是糟透了')).toBe('f2e417f09f99ee7a08fa6c8fd75f87b7969b20a60e80b04154a5aae7220c87d8')

    // 碰撞 case
    expect(sm3('丧丙上䠉䰋不亐乑')).toBe('382f78a3065187c40152d2f5ca283f8f4bf148909c763cfbdfa7efb943016552')
    expect(sm3('鱏8fpT肙腳荧HNQ')).toBe('b67a77a89564b7be13fccf456e0ec39ad564eb46f4c54c6946b1d548efc4078d')
    expect(sm3('丧丙上䠉䰋不亐乑')).not.toBe(sm3('鱏8fpT肙腳荧HNQ'))
})
