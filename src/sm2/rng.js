// Pool size must be a multiple of 4 and greater than 32.
// An array of bytes the size of the pool will be passed to init()
let psize = 256;

let pool = new Array();
let pptr;
let state;

// Initialize the pool with junk if needed.
pptr = 0;
if (window && window.navigator && window.navigator.appName == "Netscape" && window.navigator.appVersion < "5" && window.crypto) {
    // Extract entropy (256 bits) from NS4 RNG if available
    let z = crypto.random(32);
    for (let t = 0; t < z.length; t++) {
        pool[pptr++] = z.charCodeAt(t) & 255;
    }
}  
while (pptr < psize) {  // extract some randomness from Math.random()
    let t = Math.floor(65536 * Math.random());
    pool[pptr++] = t >>> 8;
    pool[pptr++] = t & 255;
}
pptr = 0;
seedTime();

class Arcfour {
    constructor() {
        this.i = 0;
        this.j = 0;
        this.S = new Array();
    }

    // Initialize arcfour context from key, an array of ints, each from [0..255]
    init(key) {
        for (let i = 0; i < 256; i++) {
            this.S[i] = i;
        }

        let j = 0;

        for (let i = 0; i < 256; i++) {
            j = (j + this.S[i] + key[i % key.length]) & 255;

            let temp = this.S[i];
            this.S[i] = this.S[j];
            this.S[j] = temp;
        }

        this.i = 0;
        this.j = 0;
    }

    next() {
        this.i = (this.i + 1) & 255;
        this.j = (this.j + this.S[this.i]) & 255;

        let temp = this.S[this.i];
        this.S[this.i] = this.S[this.j];
        this.S[this.j] = temp;

        return this.S[(this.S[this.j] + this.S[this.i]) & 255];
    }
}

// Mix in a 32-bit integer into the pool
function seedInt(x) {
    pool[pptr++] ^= x & 255;
    pool[pptr++] ^= (x >> 8) & 255;
    pool[pptr++] ^= (x >> 16) & 255;
    pool[pptr++] ^= (x >> 24) & 255;
    if (pptr >= psize) pptr -= psize;
}

// Mix in the current time (w/milliseconds) into the pool
function seedTime() {
    seedInt(+new Date());
}

function getByte() {
    if (state == null) {
        seedTime();
        state = new Arcfour();
        state.init(pool);
        for (pptr = 0; pptr < pool.length; ++pptr)
            pool[pptr] = 0;
        pptr = 0;
    }

    return state.next();
}

class SecureRandom {
    nextBytes(ba) {
        let i;
        for(i = 0; i < ba.length; ++i) ba[i] = getByte();
    }
}

module.exports = SecureRandom;
