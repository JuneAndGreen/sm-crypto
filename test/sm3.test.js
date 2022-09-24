const fs = require('fs')
const path = require('path')
const sm3 = require('../src/index').sm3

test('sm3: must match the result', () => {
    // 单字节
    expect(sm3('abc')).toBe('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
    expect(sm3('abcdefghABCDEFGH12345678')).toBe('d670c7f027fd5f9f0c163f4bfe98f9003fe597d3f52dbab0885ec2ca8dd23e9b')
    expect(sm3('abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefgh')).toBe('1cf3bafec325d7d9102cd67ba46b09195af4e613b6c2b898122363d810308b11')
    expect(sm3('abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCD')).toBe('b8ac4203969bde27434ce667b0adbf3439ee97e416e73cb96f4431f478a531fe')
    expect(sm3('abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDEFGH')).toBe('5ef0cdbe0d54426eea7f5c8b44385bb1003548735feaa59137c3dfe608aa9567')
    expect(sm3('abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd')).toBe('debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')

    // 双字节
    expect(sm3('ÁáÀàĂăẮắẰằẴẵẲẳÂâẤấẦầẪẫẨẩǍǎÅåǺǻÄäǞǟÃãȦȧǠǡĄąĀāẢảȀȁȂȃẠạẶặẬậḀḁȺⱥᶏẚɐɑᶐɒᴀÆæǼǽǢǣᴂᴁ')).toBe('175c329c05aa9e2ce3ad49551d404f670bc7fd59dfa51c748871ffd1a6b179a6')
    expect(sm3('ḂḃḄḅḆḇɃƀƁɓƂƃᵬᶀʙᴃĆćĈĉČčC̱c̱ĊċÇçḈḉȻȼƇƈɕↃↄᴄĎďḊḋḐḑḌḍḒḓḎḏÐðĐđƉɖƊɗᶑƋƌᵭȸȡᴅᴆƍʣʥʤÉéÈèĔĕÊêẾếỀềỄễỂểĚěËëẼẽĖėȨȩḜḝĘęĒēḖḗḔḕẺẻȄȅȆȇẸẹỆệḘḙḚḛɆɇᶒƎǝƏəᶕɚƐɛᶓᴈɘɜᶔɝɞʚɤᴇḞḟ')).toBe('42da89d385fa8b62bb531cccffe5a4115d3069cd3ad5f9f42f86fa8875308d2a')
    expect(sm3('ƑƒᵮᶂⅎʩǴǵĞğĜĝǦǧĠġĢģḠḡǤǥƓɠɡᶃᵹɢʛᵷƔɣƢƣĤĥȞȟḦḧḢḣḨḩḤḥḪḫH̠ẖĦħⱧⱨǶƕⱵⱶʜɦɧÍíÌìĬĭÎîǏǐÏïḮḯĨĩĮįĪīỈỉȈȉȊȋỊịḬḭƗɨĲĳɪƗᵻᶖİıƖɩᵼᴉɿĴĵɈɉJ̌ǰȷʝɟʄᴊḰḱǨǩĶķḲḳḴḵƘƙⱩⱪᶄĸʞᴋ')).toBe('323d957e0426bb388bdf83149aa99f5b80447adb27fb4514d1ffffd9c2e9f1f2')

    // 中文
    expect(sm3('你好')).toBe('78e5c78c5322ca174089e58dc7790acf8ce9d542bee6ae4a5a0797d5e356be61')
    expect(sm3('今天天气真是不错')).toBe('fff6e05118c782f5a2cea8bc2efec8819d0dc6d7d09cb9aa5c4ef14e673fa043')
    expect(sm3('今天天气真是糟透了')).toBe('f2e417f09f99ee7a08fa6c8fd75f87b7969b20a60e80b04154a5aae7220c87d8')

    // 四字节
    expect(sm3('🇨🇳𠮷😀😃😄😁😆😅')).toBe('b6d217a24511ddb7593f13b74519038618cbb5b947fee20da3f0cd5503152c23')

    // 字节数组
    expect(sm3([0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x20, 0xe6, 0x88, 0x91, 0xe6, 0x98, 0xaf, 0x20, 0x6a, 0x75, 0x6e, 0x65, 0x61, 0x6e, 0x64, 0x67, 0x72, 0x65, 0x65, 0x6e, 0x2e])).toBe('ef1cc8e36012c1f1bc18034ab778ef800e8bb1b40c7a4c7177186f6fd521110e')
    expect(sm3('hello world! 我是 juneandgreen.')).toBe('ef1cc8e36012c1f1bc18034ab778ef800e8bb1b40c7a4c7177186f6fd521110e')
    expect(sm3([0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x20, 0xe6, 0x88, 0x91, 0xe6, 0x98, 0xaf, 0x20, 0x6a, 0x75, 0x6e, 0x65, 0x61, 0x6e, 0x64, 0x67, 0x72, 0x65, 0x65, 0x6e, 0x2e])).toBe(sm3('hello world! 我是 juneandgreen.'))

    // 碰撞 case
    expect(sm3('丧丙上䠉䰋不亐乑')).toBe('382f78a3065187c40152d2f5ca283f8f4bf148909c763cfbdfa7efb943016552')
    expect(sm3('鱏8fpT肙腳荧HNQ')).toBe('b67a77a89564b7be13fccf456e0ec39ad564eb46f4c54c6946b1d548efc4078d')
    expect(sm3('丧丙上䠉䰋不亐乑')).not.toBe(sm3('鱏8fpT肙腳荧HNQ'))
})

test('sm3: long text', () => {
    const input = fs.readFileSync(path.join(__dirname, './test.jpg'))
    expect(sm3(input)).toBe('585084878e61b6b1bed61207142ea0313fa3c0c8211e44871bdaa637632ccff0')
})

test('sm3: hmac', () => {
    expect(sm3('abc', {
        key: 'daac25c1512fe50f79b0e4526b93f5c0e1460cef40b6dd44af13caec62e8c60e0d885f3c6d6fb51e530889e6fd4ac743a6d332e68a0f2a3923f42585dceb93e9',
    })).toBe('5c690e2b822a514017f1ccb9a61b6738714dbd17dbd6fdbc2fa662d122b6885d')

    expect(sm3([0x31, 0x32, 0x33, 0x34, 0x35, 0x36], {
        key: '31323334353637383930',
    })).toBe('bc1f71eef901223ae7a9718e3ae1dbf97353c81acb429b491bbdbefd2195b95e')

    const bytes8 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]

    // 32 字节
    const bytes32 = [].concat(bytes8, bytes8, bytes8, bytes8)
    expect(sm3(bytes32, {
        key: bytes32,
    })).toBe('41e6589cde89b4f8c810a820c2fb6f0ad86bf2c136a19cfb3a5c0835f598e07b')

    // 64 字节
    const bytes64 = [].concat(bytes32, bytes32)
    expect(sm3(bytes64, {
        key: bytes64,
    })).toBe('d6fb17c240930a21996373aa9fc0b1092931b016640809297911cd3f8cc9dcdd')

    // 128 字节
    const bytes128 = [].concat(bytes64, bytes64)
    expect(sm3(bytes128, {
        key: bytes128,
    })).toBe('d374f8adb0e9d1f12de94c1406fe8b2d53f84129e033f0d269400de8e8e7ca1a')
})
test('sm3: hkdf', () => {
    expect(sm3('abc', {
        mode:'hkdf',
        ikm: '0102030405060708',
        salt: '0102030405060708',
        info: '0102030405060708',
        len: 70,
    })).toBe('8def2a14158c99aec0e679409be53fa9a7868303a5572c99728c2c0a49baf6cd3ea04e5f9fd4d8af75170c0ae8a9b03b3e372a134656eec95608b3d0c8a58a4a43119fa06c99')

})
