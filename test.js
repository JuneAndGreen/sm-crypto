const asn = require('./src/util/asn1')
const util = require('./src/util/util')
const utils = require('./src/sm2/utils')
const sm2 = require('./src/sm2/index')

let publicKey = "0417C6193A31FA3772E7F83D7B1BEE40208BEBF0727ECB955F1D08C6BF29A798991DFA61CD82DFBDB966D64E2B00C4395C75A64011DDDD42FA25AFFD20F8FB7F11"
console.log(sm2.encrypt("Hello", publicKey))

let a = "306d0220145e163c65a1efe80d7cd925b7aaeef3405924cc4c14c932ebf114dcafb5cd6f0220b3f895c2c0b73149bab4f2af61a14ebe670153de1878c0c6f821870117c860510420509ae50aab52326036a3b1f6681a944869930111579344b6b7aca3137baf41780405293fcd14c1"

console.log(sm2.doEncrypt("Hello", publicKey))