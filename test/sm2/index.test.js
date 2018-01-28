const sm2 = require('../../index').sm2;

const cipherMode = 1; // 1 - C1C3C2，0 - C1C2C3

// const msgString = 'abcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH12345678abcdefghABCDEFGH12345678abcdefghABCDabcdefghABCDEFGH';
const msgString = 'absasdagfadgadsfdfdsf';
const msg = new ArrayBuffer(msgString.length);

let publicKey;
let privateKey;

describe('sm2', () => {
    beforeAll(() => {
        // 生成密钥对
        let keypair = sm2.generateKeyPairHex();

        publicKey = keypair.publicKey;
        privateKey = keypair.privateKey;
    });

    it('generate keypair', () => {
        expect(publicKey.length).toBe(130);
        expect(privateKey.length).toBe(64);
    });

    it('encrypt and decrypt data', () => {
        let encryptData = sm2.doEncrypt(msgString, publicKey, cipherMode);
        let decryptData = sm2.doDecrypt(encryptData, privateKey, cipherMode);

        expect(decryptData).toBe(msgString);
    });

    it('sign data and verify sign', () => {
        // 纯签名 + 生成椭圆曲线点
        let sigValueHex = sm2.doSignature(msg, privateKey);
        let verifyResult = sm2.doVerifySignature(msg, sigValueHex, publicKey);
        expect(verifyResult).toBe(true);
        
        // 纯签名
        let sigValueHex2 = sm2.doSignature(msg, privateKey, {
            pointPool: [sm2.getPoint(), sm2.getPoint(), sm2.getPoint(), sm2.getPoint()],
        });
        let verifyResult2 = sm2.doVerifySignature(msg, sigValueHex2, publicKey);
        expect(verifyResult2).toBe(true);

        // 纯签名 + 生成椭圆曲线点 + der编解码
        let sigValueHex3 = sm2.doSignature(msg, privateKey, {
            der: true,
        });
        let verifyResult3 = sm2.doVerifySignature(msg, sigValueHex3, publicKey, {
            der: true,
        });
        expect(verifyResult3).toBe(true);

        // 纯签名 + 生成椭圆曲线点 + sm3杂凑
        let sigValueHex4 = sm2.doSignature(msg, privateKey, {
            hash: true,
        });
        let verifyResult4 = sm2.doVerifySignature(msg, sigValueHex4, publicKey, {
            hash: true,
        });
        expect(verifyResult3).toBe(true);

        // 纯签名 + 生成椭圆曲线点 + sm3杂凑（不做公钥推导）
        let sigValueHex5 = sm2.doSignature(msg, privateKey, {
            hash: true,
            publicKey,
        });
        let verifyResult5 = sm2.doVerifySignature(msg, sigValueHex5, publicKey, {
            hash: true,
            publicKey,
        });
        expect(verifyResult3).toBe(true);
    });
})

