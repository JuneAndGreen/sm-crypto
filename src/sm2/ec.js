const { BigInteger } = require('jsbn');

/**
 * thanks for Tom Wu : http://www-cs-students.stanford.edu/~tjw/jsbn/
 *
 * Basic Javascript Elliptic Curve implementation
 * Ported loosely from BouncyCastle's Java EC code
 * Only Fp curves implemented for now
 */

const THREE = new BigInteger('3');

class ECFieldElementFp {
    constructor(q, x) {
        this.x = x;
        this.q = q;
        // TODO if(x.compareTo(q) >= 0) error
    }

    equals(other) {
        if (other === this) return true;
        return (this.q.equals(other.q) && this.x.equals(other.x));
    }

    toBigInteger() {
        return this.x;
    }

    negate() {
        return new ECFieldElementFp(this.q, this.x.negate().mod(this.q));
    }

    add(b) {
        return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q));
    }

    subtract(b) {
        return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q));
    }

    multiply(b) {
        return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q));
    }

    square() {
        return new ECFieldElementFp(this.q, this.x.square().mod(this.q));
    }

    divide(b) {
        return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q));
    }
}

class ECPointFp {
    constructor(curve, x, y, z) {
        this.curve = curve;
        this.x = x;
        this.y = y;
        // Projective coordinates: either zinv == null or z * zinv == 1
        // z and zinv are just BigIntegers, not fieldElements
        this.z = z == null ? BigInteger.ONE : z;
        this.zinv = null;
        //TODO: compression flag
    }

    getX() {
        if (this.zinv === null) this.zinv = this.z.modInverse(this.curve.q);

        return this.curve.fromBigInteger(this.x.toBigInteger().multiply(this.zinv).mod(this.curve.q));
    }

    getY() {
        if (this.zinv === null) this.zinv = this.z.modInverse(this.curve.q);

        return this.curve.fromBigInteger(this.y.toBigInteger().multiply(this.zinv).mod(this.curve.q));
    }

    equals(other) {
        if (other === this) return true;
        if (this.isInfinity()) return other.isInfinity();
        if (other.isInfinity()) return this.isInfinity();

        // u = Y2 * Z1 - Y1 * Z2
        let u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z)).mod(this.curve.q);
        if (!u.equals(BigInteger.ZERO)) return false;

        // v = X2 * Z1 - X1 * Z2
        let v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z)).mod(this.curve.q);
        return v.equals(BigInteger.ZERO);
    }

    isInfinity() {
        if ((this.x == null) && (this.y == null)) return true;
        return this.z.equals(BigInteger.ZERO) && !this.y.toBigInteger().equals(BigInteger.ZERO);
    }

    negate() {
        return new ECPointFp(this.curve, this.x, this.y.negate(), this.z);
    }

    add(b) {
        if (this.isInfinity()) return b;
        if (b.isInfinity()) return this;

        // u = Y2 * Z1 - Y1 * Z2
        let u = b.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(b.z)).mod(this.curve.q);
        // v = X2 * Z1 - X1 * Z2
        let v = b.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(b.z)).mod(this.curve.q);

        if(BigInteger.ZERO.equals(v)) {
            if(BigInteger.ZERO.equals(u)) {
                return this.twice(); // this == b, so double
            }
            return this.curve.getInfinity(); // this = -b, so infinity
        }

        let x1 = this.x.toBigInteger();
        let y1 = this.y.toBigInteger();
        let x2 = b.x.toBigInteger();
        let y2 = b.y.toBigInteger();

        let v2 = v.square();
        let v3 = v2.multiply(v);
        let x1v2 = x1.multiply(v2);
        let zu2 = u.square().multiply(this.z);

        // x3 = v * (z2 * (z1 * u^2 - 2 * x1 * v^2) - v^3)
        let x3 = zu2.subtract(x1v2.shiftLeft(1)).multiply(b.z).subtract(v3).multiply(v).mod(this.curve.q);
        // y3 = z2 * (3 * x1 * u * v^2 - y1 * v^3 - z1 * u^3) + u * v^3
        let y3 = x1v2.multiply(THREE).multiply(u).subtract(y1.multiply(v3)).subtract(zu2.multiply(u)).multiply(b.z).add(u.multiply(v3)).mod(this.curve.q);
        // z3 = v^3 * z1 * z2
        let z3 = v3.multiply(this.z).multiply(b.z).mod(this.curve.q);

        return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
    }

    twice() {
        if (this.isInfinity()) return this;
        if (this.y.toBigInteger().signum() == 0) return this.curve.getInfinity();

        let x1 = this.x.toBigInteger();
        let y1 = this.y.toBigInteger();

        let y1z1 = y1.multiply(this.z);
        let y1sqz1 = y1z1.multiply(y1).mod(this.curve.q);
        let a = this.curve.a.toBigInteger();

        // w = 3 * x1^2 + a * z1^2
        let w = x1.square().multiply(THREE);
        if (!BigInteger.ZERO.equals(a)) {
            w = w.add(this.z.square().multiply(a));
        }
        w = w.mod(this.curve.q);
        // x3 = 2 * y1 * z1 * (w^2 - 8 * x1 * y1^2 * z1)
        let x3 = w.square().subtract(x1.shiftLeft(3).multiply(y1sqz1)).shiftLeft(1).multiply(y1z1).mod(this.curve.q);
        // y3 = 4 * y1^2 * z1 * (3 * w * x1 - 2 * y1^2 * z1) - w^3
        let y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(w.square().multiply(w)).mod(this.curve.q);
        // z3 = 8 * (y1 * z1)^3
        let z3 = y1z1.square().multiply(y1z1).shiftLeft(3).mod(this.curve.q);

        return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
    }

    multiply(k) {
        // Simple NAF (Non-Adjacent Form) multiplication algorithm
        if (this.isInfinity()) return this;
        if (k.signum() == 0) return this.curve.getInfinity();

        let e = k;
        let h = e.multiply(new BigInteger('3'));

        let neg = this.negate();
        let R = this;

        for (let i = h.bitLength() - 2; i > 0; --i) {
            R = R.twice();

            let hBit = h.testBit(i);
            let eBit = e.testBit(i);

            if (hBit != eBit) {
                R = R.add(hBit ? this : neg);
            }
        }

        return R;
    }

    multiplyTwo(j, x, k) {
        // Compute this * j + x * k (simultaneous multiplication)
        let i = j.bitLength() > k.bitLength() ? j.bitLength() - 1 : k.bitLength() - 1;
        let R = this.curve.getInfinity();
        let both = this.add(x);
        while (i >= 0) {
            R = R.twice();
            if (j.testBit(i)) {
                if (k.testBit(i)) R = R.add(both);
                else R = R.add(this);
            } else {
                if (k.testBit(i)) R = R.add(x);
            }
            --i;
        }

        return R;
    }

    static decodeFromHex(curve, encHex) {
        let type = encHex.substr(0, 2); // shall be '04'
        let dataLen = encHex.length - 2;

        // Extract x and y as byte arrays
        let xHex = encHex.substr(2, dataLen / 2);
        let yHex = encHex.substr(2 + dataLen / 2, dataLen / 2);

        // Convert to BigIntegers
        let x = new BigInteger(xHex, 16);
        let y = new BigInteger(yHex, 16);

        // Return point
        return new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
    }
}

class ECCurveFp {
    constructor(q, a, b) {
        this.q = q;
        this.a = this.fromBigInteger(a);
        this.b = this.fromBigInteger(b);
        this.infinity = new ECPointFp(this, null, null);
    }

    getQ() {
        return this.q;
    }

    getA() {
        return this.a;
    }

    getB() {
        return this.b;
    }

    equals(other) {
        if (other === this) return true;
        return(this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b));
    }

    getInfinity() {
        return this.infinity;
    }

    fromBigInteger(x) {
        return new ECFieldElementFp(this.q, x);
    }

    decodePointHex(s) {
        // for now, work with hex strings because they're easier in JS
        switch (parseInt(s.substr(0,2), 16)) {
            // first byte
            case 0:
                return this.infinity;
            case 2:
            case 3:
                // point compression not supported yet
                return null;
            case 4:
            case 6:
            case 7:
                var len = (s.length - 2) / 2;
                var xHex = s.substr(2, len);
                var yHex = s.substr(len+2, len);

                return new ECPointFp(this, this.fromBigInteger(new BigInteger(xHex, 16)), this.fromBigInteger(new BigInteger(yHex, 16)));

            default: // unsupported
                return null;
        }
    }
}

module.exports = {
    ECFieldElementFp,
    ECPointFp,
    ECCurveFp,
};
