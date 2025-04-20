const BLOCK_WORDS = 16;
const BUF_BLOCKS = 4;
const BUF_WORDS = BLOCK_WORDS * BUF_BLOCKS;
const STATE_WORDS = 16;
const U32_MASK = 0xffffffffn;
const U64_MASK = (1n << 64n) - 1n;

function rotr32(x: number, n: number): number {
    return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function wmul64(a: bigint, b: bigint): { hi: bigint, lo: bigint } {
    const result = a * b;
    const hi = result >> 64n;
    const lo = result & U64_MASK;
    return { hi, lo };
}

class ChaChaCore {
    private state: Uint32Array;
    private rounds: number;

    constructor(seed: Uint8Array, nonce: Uint8Array, rounds: number) {
        if (seed.length !== 32) throw new Error("Seed must be 32 bytes");
        if (nonce.length !== 8 && nonce.length !== 12) throw new Error("Nonce must be 8 or 12 bytes");
        this.rounds = rounds / 2;
        this.state = new Uint32Array(STATE_WORDS);
        this.state[0] = 0x61707865;
        this.state[1] = 0x3320646e;
        this.state[2] = 0x79622d32;
        this.state[3] = 0x6b206574;
        const seedView = new DataView(seed.buffer, seed.byteOffset, seed.byteLength);
        for (let i = 0; i < 8; i++) {
            this.state[4 + i] = seedView.getUint32(i * 4, true);
        }
        this.state[12] = 0;
        this.state[13] = 0;
        const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
        if (nonce.length === 12) {
            this.state[13] = nonceView.getUint32(0, true);
            this.state[14] = nonceView.getUint32(4, true);
            this.state[15] = nonceView.getUint32(8, true);
            this.state[12] = 0;
        } else {
            this.state[14] = nonceView.getUint32(0, true);
            this.state[15] = nonceView.getUint32(4, true);
            this.state[12] = 0;
            this.state[13] = 0;
        }
    }

    private quarterRound(state: Uint32Array, a: number, b: number, c: number, d: number): void {
        state[a] = (state[a] + state[b]) >>> 0; state[d] = rotr32(state[d] ^ state[a], 16);
        state[c] = (state[c] + state[d]) >>> 0; state[b] = rotr32(state[b] ^ state[c], 20);
        state[a] = (state[a] + state[b]) >>> 0; state[d] = rotr32(state[d] ^ state[a], 24);
        state[c] = (state[c] + state[d]) >>> 0; state[b] = rotr32(state[b] ^ state[c], 25);
    }

    private coreRound(state: Uint32Array): void {
        this.quarterRound(state, 0, 4, 8, 12);
        this.quarterRound(state, 1, 5, 9, 13);
        this.quarterRound(state, 2, 6, 10, 14);
        this.quarterRound(state, 3, 7, 11, 15);
        this.quarterRound(state, 0, 5, 10, 15);
        this.quarterRound(state, 1, 6, 11, 12);
        this.quarterRound(state, 2, 7, 8, 13);
        this.quarterRound(state, 3, 4, 9, 14);
    }

    generate(results: Uint32Array): void {
        if (results.length !== BUF_WORDS) throw new Error("Results buffer must have size " + BUF_WORDS);
        const workingState = new Uint32Array(STATE_WORDS);
        const blockInputState = new Uint32Array(this.state);

        for (let block = 0; block < BUF_BLOCKS; block++) {
            workingState.set(blockInputState);
            for (let i = 0; i < this.rounds; i++) {
                this.coreRound(workingState);
            }
            const offset = block * BLOCK_WORDS;
            for (let i = 0; i < STATE_WORDS; i++) {
                results[offset + i] = (workingState[i] + blockInputState[i]) >>> 0;
            }
            blockInputState[12] = (blockInputState[12] + 1) >>> 0;
            if (blockInputState[12] === 0) {
                blockInputState[13] = (blockInputState[13] + 1) >>> 0;
            }
        }
        this.state[12] = blockInputState[12];
        this.state[13] = blockInputState[13];
    }

    getBlockPos(): bigint {
        const low = BigInt(this.state[12]);
        const high = BigInt(this.state[13]);
        return (high << 32n) | low;
    }

    setBlockPos(value: bigint): void {
        this.state[12] = Number(value & U32_MASK);
        this.state[13] = Number((value >> 32n) & U32_MASK);
    }

     getNonce(): bigint {
       const low = BigInt(this.state[14]);
       const high = BigInt(this.state[15]);
       return (high << 32n) | low;
     }

     setNonce(value: bigint): void {
       this.state[14] = Number(value & U32_MASK);
       this.state[15] = Number((value >> 32n) & U32_MASK);
     }

    getSeed(): Uint8Array {
        const seed = new Uint8Array(32);
        const view = new DataView(seed.buffer);
        for (let i = 0; i < 8; i++) {
            view.setUint32(i * 4, this.state[4 + i], true);
        }
        return seed;
    }

    clone(): ChaChaCore {
      const newCore = Object.create(ChaChaCore.prototype);
      newCore.state = this.state.slice();
      newCore.rounds = this.rounds;
      return newCore;
    }
}

/**
 * A cryptographically secure random number generator that uses the ChaCha algorithm.
 * Based on the Rust `rand_chacha` crate implementation.
 */
export class ChaChaRng {
    private core: ChaChaCore;
    private buffer: Uint32Array;
    private index: number;
    private rounds: number;

    private constructor(core: ChaChaCore, rounds: number) {
        this.core = core;
        this.buffer = new Uint32Array(BUF_WORDS);
        this.index = BUF_WORDS;
        this.rounds = rounds;
    }

    /**
     * Creates a new ChaChaRng instance from a 32-byte seed.
     * Uses a default nonce (stream ID 0).
     * @param seed The 32-byte seed.
     * @param rounds The number of rounds (8, 12, or 20).
     * @returns A new ChaChaRng instance.
     */
    static fromSeed(seed: Uint8Array, rounds: 8 | 12 | 20): ChaChaRng {
        const defaultNonce = new Uint8Array(8);
        const core = new ChaChaCore(seed, defaultNonce, rounds);
        return new ChaChaRng(core, rounds);
    }

    /**
     * Creates a new ChaChaRng instance from a 64-bit integer seed.
     * Uses a simple seeding algorithm derived from PCG to initialize the 32-byte seed.
     * @param state The initial 64-bit seed value (as bigint).
     * @param rounds The number of rounds (8, 12, or 20).
     * @returns A new ChaChaRng instance.
     */
    static fromU64Seed(state: bigint, rounds: 8 | 12 | 20): ChaChaRng {
        const seed = new Uint8Array(32);
        const stateObj = { value: state };
        for (let i = 0; i < 8; i++) {
            const x = ChaChaRng.pcg32(stateObj);
            const view = new DataView(seed.buffer, i * 4, 4);
            view.setUint32(0, x, true);
        }
        return ChaChaRng.fromSeed(seed, rounds);
    }

    private static pcg32(state: { value: bigint }): number {
        const MUL = 6364136223846793005n;
        const INC = 11634580027462260723n;
        state.value = (state.value * MUL + INC) & U64_MASK;
        const s = state.value;
        const xorshifted = Number((((s >> 18n) ^ s) >> 27n) & U32_MASK);
        const rot = Number((s >> 59n) & 0x1Fn);
        const x = (xorshifted >>> rot) | (xorshifted << (32 - rot) & 0xFFFFFFFF);
        return x >>> 0;
    }

    private refill(): void {
        this.core.generate(this.buffer);
        this.index = 0;
    }

    /**
     * Generates the next random u32 value.
     * @returns A random unsigned 32-bit integer.
     */
    nextU32(): number {
        if (this.index >= BUF_WORDS) {
            this.refill();
        }
        const val = this.buffer[this.index];
        this.index++;
        return val;
    }

    /**
     * Generates the next random u64 value (as bigint).
     * @returns A random unsigned 64-bit integer (bigint).
     */
    nextU64(): bigint {
        const low = BigInt(this.nextU32());
        const high = BigInt(this.nextU32());
        return (high << 32n) | low;
    }

    /**
     * Fills the given byte array with random bytes.
     * @param bytes The Uint8Array to fill.
     */
    fillBytes(bytes: Uint8Array): void {
        const len = bytes.length;
        let offset = 0;
        while (offset < len) {
            if (this.index >= BUF_WORDS) {
                this.refill();
            }
            const bufferRemainingWords = BUF_WORDS - this.index;
            const bufferRemainingBytes = bufferRemainingWords * 4;
            const bytesToCopy = Math.min(len - offset, bufferRemainingBytes);
            const internalBufferAsBytes = new Uint8Array(this.buffer.buffer, this.buffer.byteOffset + this.index * 4, bytesToCopy);
             bytes.set(internalBufferAsBytes, offset);
             const wordsCopied = Math.ceil(bytesToCopy / 4);
             this.index += wordsCopied;
             offset += bytesToCopy;
        }
    }

    /**
     * Generates a random u64 (bigint) within the specified range.
     * Matches the behavior of Rust's `rand::Rng::gen_range` for u64, using
     * Canon's method (potentially biased, matching Rust's default).
     * @param low The lower bound of the range (inclusive).
     * @param high The upper bound of the range.
     * @param inclusive If true, the range is [low, high]. If false, the range is [low, high). Defaults to false.
     * @returns A random bigint within the specified range.
     * @throws Error if the range is invalid (e.g., low > high).
     */
    genRangeU64(low: bigint, high: bigint, inclusive: boolean = false): bigint {
        let effectiveHigh = high;
        if (!inclusive) {
             if (!(low < high)) {
                throw new Error("Upper bound must be strictly greater than lower bound for exclusive range");
             }
             effectiveHigh = high - 1n;
        } else {
            if (!(low <= high)) {
                throw new Error("Upper bound must be greater than or equal to lower bound for inclusive range");
            }
        }

        const rangeSize = (effectiveHigh - low + 1n) & U64_MASK;

        if (rangeSize === 0n) {
            return this.nextU64();
        }

        const { hi: resultHi, lo: resultLo } = wmul64(this.nextU64(), rangeSize);
        let finalResult = resultHi;

        const negRange = (-rangeSize) & U64_MASK;
        if (resultLo > negRange) {
            const { hi: newHiOrder } = wmul64(this.nextU64(), rangeSize);
            const checkAdd = resultLo + newHiOrder;
            const isOverflow = checkAdd > U64_MASK;
            if (isOverflow) {
                finalResult = (finalResult + 1n) & U64_MASK;
            }
        }

        return (low + finalResult) & U64_MASK;
    }

    /**
     * Alias for genRangeU64. Generates a random u64 (bigint) within the specified range.
     * Matches the behavior of Rust's `rand::Rng::gen_range` for u64.
     * @param low The lower bound of the range (inclusive).
     * @param high The upper bound of the range.
     * @param inclusive If true, the range is [low, high]. If false, the range is [low, high). Defaults to false.
     * @returns A random bigint within the specified range.
     * @throws Error if the range is invalid (e.g., low > high).
     */
    gen_range_u64(low: bigint, high: bigint, inclusive: boolean = false): bigint {
        return this.genRangeU64(low, high, inclusive);
    }

    /**
     * Generates a random u32 within the specified exclusive range [low, high).
     * Uses rejection sampling for unbiased results.
     * @param low The lower bound (inclusive).
     * @param high The upper bound (exclusive).
     * @returns A random number within the range.
     * @throws Error if low >= high.
     */
    genRangeU32(low: number, high: number): number {
        if (!(low < high)) {
            throw new Error("Low must be less than high for exclusive range");
        }
        const range = high - low;
        if (range === 0 || !Number.isFinite(range)) {
            return low;
        }
        const range_u32 = range >>> 0;
        if ((range_u32 & (range_u32 - 1)) === 0) {
             const mask = range_u32 - 1;
            return (low + (this.nextU32() & mask)) >>> 0;
        }
        const rangeLimit = (0xFFFFFFFF - (0xFFFFFFFF % range_u32));
        let x: number;
        do {
            x = this.nextU32();
        } while (x >= rangeLimit);
        return (low + (x % range_u32)) >>> 0;
    }

    /**
     * Generates a random i32 within the specified exclusive range [low, high).
     * @param low The lower bound (inclusive).
     * @param high The upper bound (exclusive).
     * @returns A random number within the range.
     * @throws Error if low >= high.
     */
    genRangeI32(low: number, high: number): number {
         if (!(low < high)) {
             throw new Error("Low must be less than high for exclusive range");
         }
         const range = high - low;
         if (range <= 0 || !Number.isFinite(range)) {
             return low;
         }
         const range_u32 = range >>> 0;
         return low + this.genRangeU32(0, range_u32);
    }

    /**
     * Generates a random i64 (bigint) within the specified exclusive range [low, high).
     * @param low The lower bound (inclusive).
     * @param high The upper bound (exclusive).
     * @returns A random bigint within the range.
     * @throws Error if low >= high.
     */
     genRangeI64(low: bigint, high: bigint): bigint {
         if (!(low < high)) {
             throw new Error("Low must be less than high for exclusive range");
         }
         const range = high - low;
         if (range <= 0n) {
             return low;
         }
         // Generate offset in [0, range-1] inclusive
         const offset = this.genRangeU64(0n, range -1n, true);
         return low + offset;
     }

    /**
     * Generates a random f64 (number) within the specified exclusive range [low, high).
     * Uses 53 bits of precision from the generator.
     * @param low The lower bound (inclusive).
     * @param high The upper bound (exclusive).
     * @returns A random number within the range.
     * @throws Error if low >= high or bounds are not finite.
     */
    genRangeF64(low: number, high: number): number {
         if (!(low < high)) {
             throw new Error("Low must be less than high for exclusive range");
         }
         if (!Number.isFinite(low) || !Number.isFinite(high)) {
             throw new Error("Range bounds must be finite");
         }
         const randomU64 = this.nextU64();
         const random53bit = randomU64 >> (64n - 53n);
         const scale = Number(random53bit) / Number(1n << 53n);
         return low + scale * (high - low);
    }

    /**
     * Gets the current position within the generator's output stream, measured in 32-bit words.
     * This is a 68-bit value (combining the 64-bit block counter and 4-bit word index within a block).
     * @returns The current absolute word position as a bigint.
     */
    getWordPos(): bigint {
        const bufEndBlock = this.core.getBlockPos();
        const bufStartBlock = (bufEndBlock - BigInt(BUF_BLOCKS)) & U64_MASK;
        const bufOffsetWords = BigInt(this.index);
        const blocksConsumed = bufOffsetWords / BigInt(BLOCK_WORDS);
        const wordsConsumedInBlock = bufOffsetWords % BigInt(BLOCK_WORDS);
        const currentBlock = (bufStartBlock + blocksConsumed) & U64_MASK;
        const currentWordPos = (currentBlock * BigInt(BLOCK_WORDS)) + wordsConsumedInBlock;
        return currentWordPos;
    }

    /**
     * Sets the current position within the generator's output stream.
     * The position is measured in 32-bit words from the beginning of the stream.
     * This will refill the internal buffer.
     * @param wordOffset The absolute word position to seek to (as bigint).
     */
    setWordPos(wordOffset: bigint): void {
        const targetBlock = wordOffset / BigInt(BLOCK_WORDS);
        const wordIndexInBlock = Number(wordOffset % BigInt(BLOCK_WORDS));
        this.core.setBlockPos(targetBlock);
        this.refill();
        this.index = Math.min(Math.max(wordIndexInBlock, 0), BUF_WORDS);
    }

    /**
     * Sets the stream number (nonce). This allows generating multiple independent sequences
     * from the same seed.
     * Behavior matches Rust's rand_chacha: if the buffer is not fully consumed,
     * the current position is preserved, but future generated blocks will use the new stream ID.
     * @param stream The 64-bit stream ID (as bigint).
     */
    setStream(stream: bigint): void {
        this.core.setNonce(stream);
        if (this.index < BUF_WORDS) {
             const wp = this.getWordPos();
             this.setWordPos(wp);
        }
    }

    /**
     * Gets the current stream number (nonce).
     * @returns The current 64-bit stream ID (as bigint).
     */
    getStream(): bigint {
        return this.core.getNonce();
    }

    /**
     * Gets the seed used to initialize the generator.
     * @returns The 32-byte seed as a Uint8Array.
     */
    getSeed(): Uint8Array {
        return this.core.getSeed();
    }

    /**
     * Creates a clone of the current RNG state. The clone will produce the
     * same sequence of numbers as the original from this point forward.
     * @returns A new ChaChaRng instance with the same state.
     */
    clone(): ChaChaRng {
        const newRng = Object.create(ChaChaRng.prototype);
        newRng.core = this.core.clone();
        newRng.buffer = this.buffer.slice();
        newRng.index = this.index;
        newRng.rounds = this.rounds;
        return newRng;
    }
}

/** Factory function for ChaCha8Rng. */
export const ChaCha8Rng = (seed: Uint8Array) => ChaChaRng.fromSeed(seed, 8);
/** Factory function for ChaCha12Rng. */
export const ChaCha12Rng = (seed: Uint8Array) => ChaChaRng.fromSeed(seed, 12);
/** Factory function for ChaCha20Rng. */
export const ChaCha20Rng = (seed: Uint8Array) => ChaChaRng.fromSeed(seed, 20);

