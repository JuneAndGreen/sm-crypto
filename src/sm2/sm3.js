const { BigInteger } = require('jsbn');
const _ = require('./utils');

let copyArray = function (sourceArray, sourceIndex, destinationArray, destinationIndex, length) {
    for (let i = 0; i < length; i++) destinationArray[destinationIndex + i] = sourceArray[sourceIndex + i];
};

const Int32 = {
    minValue: -parseInt('10000000000000000000000000000000', 2),
    maxValue: parseInt('1111111111111111111111111111111', 2),
    parse: function (n) {
        if (n < this.minValue) {
            let bigInteger = new Number(-n);
            let bigIntegerRadix = bigInteger.toString(2);
            let subBigIntegerRadix = bigIntegerRadix.substr(bigIntegerRadix.length - 31, 31);
            let reBigIntegerRadix = '';
            for (let i = 0; i < subBigIntegerRadix.length; i++) {
                let subBigIntegerRadixItem = subBigIntegerRadix.substr(i, 1);
                reBigIntegerRadix += subBigIntegerRadixItem == '0' ? '1' : '0'
            }
            let result = parseInt(reBigIntegerRadix, 2);
            return (result + 1)
        } else if (n > this.maxValue) {
            let bigInteger = Number(n);
            let bigIntegerRadix = bigInteger.toString(2);
            let subBigIntegerRadix = bigIntegerRadix.substr(bigIntegerRadix.length - 31, 31);
            let reBigIntegerRadix = '';
            for (let i = 0; i < subBigIntegerRadix.length; i++) {
                let subBigIntegerRadixItem = subBigIntegerRadix.substr(i, 1);
                reBigIntegerRadix += subBigIntegerRadixItem == '0' ? '1' : '0'
            }
            let result = parseInt(reBigIntegerRadix, 2);
            return -(result + 1)
        } else {
            return n
        }
    },
    parseByte: function (n) {
        if (n < 0) {
            let bigInteger = new Number(-n);
            let bigIntegerRadix = bigInteger.toString(2);
            let subBigIntegerRadix = bigIntegerRadix.substr(bigIntegerRadix.length - 8, 8);
            let reBigIntegerRadix = '';
            for (let i = 0; i < subBigIntegerRadix.length; i++) {
                let subBigIntegerRadixItem = subBigIntegerRadix.substr(i, 1);
                reBigIntegerRadix += subBigIntegerRadixItem == '0' ? '1' : '0'
            }
            let result = parseInt(reBigIntegerRadix, 2);
            return (result + 1)
        } else if (n > 255) {
            let bigInteger = Number(n);
            let bigIntegerRadix = bigInteger.toString(2);
            return parseInt(bigIntegerRadix.substr(bigIntegerRadix.length - 8, 8), 2)
        } else {
            return n
        }
    }
};

class SM3Digest {
    constructor() {
        this.xBuf = new Array();
        this.xBufOff = 0;
        this.byteCount = 0;
        this.DIGEST_LENGTH = 32;
        this.v0 = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e];
        this.v0 = [0x7380166f, 0x4914b2b9, 0x172442d7, -628488704, -1452330820, 0x163138aa, -477237683, -1325724082];
        this.v = new Array(8);
        this.v_ = new Array(8);
        this.X0 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        this.X = new Array(68);
        this.xOff = 0;
        this.T_00_15 = 0x79cc4519;
        this.T_16_63 = 0x7a879d8a;
        if (arguments.length > 0) {
            this.initDigest(arguments[0])
        } else {
            this.init()
        }
    }

    init() {
        this.xBuf = new Array(4);
        this.reset()
    }

    initDigest(t) {
        this.xBuf = [].concat(t.xBuf);
        this.xBufOff = t.xBufOff;
        this.byteCount = t.byteCount;
        copyArray(t.X, 0, this.X, 0, t.X.length);
        this.xOff = t.xOff;
        copyArray(t.v, 0, this.v, 0, t.v.length);
    }

    getDigestSize() {
        return this.DIGEST_LENGTH
    }

    reset() {
        this.byteCount = 0;
        this.xBufOff = 0;
        for (let elem in this.xBuf) this.xBuf[elem] = null;
        copyArray(this.v0, 0, this.v, 0, this.v0.length);
        this.xOff = 0;
        copyArray(this.X0, 0, this.X, 0, this.X0.length);
    }

    processBlock() {
        let i;
        let ww = this.X;
        let ww_ = new Array(64);
        for (i = 16; i < 68; i++) {
            ww[i] = this.p1(ww[i - 16] ^ ww[i - 9] ^ (this.rotate(ww[i - 3], 15))) ^ (this.rotate(ww[i - 13], 7)) ^ ww[
                i - 6];
        }
        for (i = 0; i < 64; i++) {
            ww_[i] = ww[i] ^ ww[i + 4];
        }
        let vv = this.v;
        let vv_ = this.v_;
        copyArray(vv, 0, vv_, 0, this.v0.length);
        let SS1, SS2, TT1, TT2, aaa;
        for (i = 0; i < 16; i++) {
            aaa = this.rotate(vv_[0], 12);
            SS1 = Int32.parse(Int32.parse(aaa + vv_[4]) + this.rotate(this.T_00_15, i));
            SS1 = this.rotate(SS1, 7);
            SS2 = SS1 ^ aaa;
            TT1 = Int32.parse(Int32.parse(this.ff_00_15(vv_[0], vv_[1], vv_[2]) + vv_[3]) + SS2) + ww_[i];
            TT2 = Int32.parse(Int32.parse(this.gg_00_15(vv_[4], vv_[5], vv_[6]) + vv_[7]) + SS1) + ww[i];
            vv_[3] = vv_[2];
            vv_[2] = this.rotate(vv_[1], 9);
            vv_[1] = vv_[0];
            vv_[0] = TT1;
            vv_[7] = vv_[6];
            vv_[6] = this.rotate(vv_[5], 19);
            vv_[5] = vv_[4];
            vv_[4] = this.p0(TT2);
        }
        for (i = 16; i < 64; i++) {
            aaa = this.rotate(vv_[0], 12);
            SS1 = Int32.parse(Int32.parse(aaa + vv_[4]) + this.rotate(this.T_16_63, i));
            SS1 = this.rotate(SS1, 7);
            SS2 = SS1 ^ aaa;
            TT1 = Int32.parse(Int32.parse(this.ff_16_63(vv_[0], vv_[1], vv_[2]) + vv_[3]) + SS2) + ww_[i];
            TT2 = Int32.parse(Int32.parse(this.gg_16_63(vv_[4], vv_[5], vv_[6]) + vv_[7]) + SS1) + ww[i];
            vv_[3] = vv_[2];
            vv_[2] = this.rotate(vv_[1], 9);
            vv_[1] = vv_[0];
            vv_[0] = TT1;
            vv_[7] = vv_[6];
            vv_[6] = this.rotate(vv_[5], 19);
            vv_[5] = vv_[4];
            vv_[4] = this.p0(TT2);
        }
        for (i = 0; i < 8; i++) {
            vv[i] ^= Int32.parse(vv_[i]);
        }
        this.xOff = 0;
        copyArray(this.X0, 0, this.X, 0, this.X0.length);
    }

    processWord(in_Renamed, inOff) {
        let n = in_Renamed[inOff] << 24;
        n |= (in_Renamed[++inOff] & 0xff) << 16;
        n |= (in_Renamed[++inOff] & 0xff) << 8;
        n |= (in_Renamed[++inOff] & 0xff);
        this.X[this.xOff] = n;
        if (++this.xOff == 16) {
            this.processBlock();
        }
    }

    processLength(bitLength) {
        if (this.xOff > 14) {
            this.processBlock();
        }
        this.X[14] = (this.urShiftLong(bitLength, 32));
        this.X[15] = (bitLength & (0xffffffff))
    }

    intToBigEndian(n, bs, off) {
        bs[off] = Int32.parseByte(this.urShift(n, 24));
        bs[++off] = Int32.parseByte(this.urShift(n, 16));
        bs[++off] = Int32.parseByte(this.urShift(n, 8));
        bs[++off] = Int32.parseByte(n);
    }

    doFinal(out_Renamed, outOff) {
        this.finish();
        for (let i = 0; i < 8; i++) {
            this.intToBigEndian(this.v[i], out_Renamed, outOff + i * 4);
        }
        this.reset();
        return this.DIGEST_LENGTH;
    }

    update(input) {
        this.xBuf[this.xBufOff++] = input;
        if (this.xBufOff == this.xBuf.length) {
            this.processWord(this.xBuf, 0);
            this.xBufOff = 0;
        }
        this.byteCount++;
    }

    blockUpdate(input, inOff, length) {
        while ((this.xBufOff != 0) && (length > 0)) {
            this.update(input[inOff]);
            inOff++;
            length--;
        }
        while (length > this.xBuf.length) {
            this.processWord(input, inOff);
            inOff += this.xBuf.length;
            length -= this.xBuf.length;
            this.byteCount += this.xBuf.length;
        }
        while (length > 0) {
            this.update(input[inOff]);
            inOff++;
            length--;
        }
    }

    finish() {
        let bitLength = (this.byteCount << 3);
        this.update((128));
        while (this.xBufOff != 0) this.update((0));
        this.processLength(bitLength);
        this.processBlock();
    }

    rotate(x, n) {
        return (x << n) | (this.urShift(x, (32 - n)));
    }

    p0(X) {
        return ((X) ^ this.rotate((X), 9) ^ this.rotate((X), 17));
    }

    p1(X) {
        return ((X) ^ this.rotate((X), 15) ^ this.rotate((X), 23));
    }

    ff_00_15(X, Y, Z) {
        return (X ^ Y ^ Z);
    }

    ff_16_63(X, Y, Z) {
        return ((X & Y) | (X & Z) | (Y & Z));
    }

    gg_00_15(X, Y, Z) {
        return (X ^ Y ^ Z);
    }

    gg_16_63(X, Y, Z) {
        return ((X & Y) | (~X & Z));
    }

    urShift(number, bits) {
        if (number > Int32.maxValue || number < Int32.minValue) {
            number = Int32.parse(number);
        }
        if (number >= 0) {
            return number >> bits;
        } else {
            return (number >> bits) + (2 << ~bits);
        }
    }

    urShiftLong(number, bits) {
        let returnV;
        let big = new BigInteger();
        big.fromInt(number);
        if (big.signum() >= 0) {
            returnV = big.shiftRight(bits).intValue();
        } else {
            let bigAdd = new BigInteger();
            bigAdd.fromInt(2);
            let shiftLeftBits = ~bits;
            let shiftLeftNumber = '';
            if (shiftLeftBits < 0) {
                let shiftRightBits = 64 + shiftLeftBits;
                for (let i = 0; i < shiftRightBits; i++) {
                    shiftLeftNumber += '0';
                }
                let shiftLeftNumberBigAdd = new BigInteger();
                shiftLeftNumberBigAdd.fromInt(number >> bits);
                let shiftLeftNumberBig = new BigInteger("10" + shiftLeftNumber, 2);
                shiftLeftNumber = shiftLeftNumberBig.toRadix(10);
                let r = shiftLeftNumberBig.add(shiftLeftNumberBigAdd);
                returnV = r.toRadix(10);
            } else {
                shiftLeftNumber = bigAdd.shiftLeft((~bits)).intValue();
                returnV = (number >> bits) + shiftLeftNumber;
            }
        }
        return returnV;
    }

    getZ(g, publicKey) {
        let userId = _.parseUtf8StringToHex('1234567812345678');
        let len = userId.length * 4;
        this.update((len >> 8 & 0x00ff));
        this.update((len & 0x00ff));
        let userIdWords = _.hexToArray(userId);
        this.blockUpdate(userIdWords, 0, userIdWords.length);
        let aWords = _.hexToArray(g.curve.a.toBigInteger().toRadix(16));
        let bWords = _.hexToArray(g.curve.b.toBigInteger().toRadix(16));
        let gxWords = _.hexToArray(g.getX().toBigInteger().toRadix(16));
        let gyWords = _.hexToArray(g.getY().toBigInteger().toRadix(16));
        let pxWords = _.hexToArray(publicKey.substr(0, 64));
        let pyWords = _.hexToArray(publicKey.substr(64, 64));
        this.blockUpdate(aWords, 0, aWords.length);
        this.blockUpdate(bWords, 0, bWords.length);
        this.blockUpdate(gxWords, 0, gxWords.length);
        this.blockUpdate(gyWords, 0, gyWords.length);
        this.blockUpdate(pxWords, 0, pxWords.length);
        this.blockUpdate(pyWords, 0, pyWords.length);
        let md = new Array(this.getDigestSize());
        this.doFinal(md, 0);
        return md;
    }
}

module.exports = SM3Digest;
