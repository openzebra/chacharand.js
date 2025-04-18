const BLOCK_WORDS = 16;
const BUF_BLOCKS = 4;
const BUF_WORDS = BLOCK_WORDS * BUF_BLOCKS;

const STATE_WORDS = 16;

const U32_MASK = 0xffffffffn;
const U64_MASK = 0xffffffffffffffffn;

function rotr32(x: number, n: number): number {
    return ((x >>> n) | (x << (32 - n))) >>> 0;
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
             this.state[12] = nonceView.getUint32(0, true);
             this.state[14] = nonceView.getUint32(4, true);
             this.state[15] = nonceView.getUint32(8, true);
        } else { // 8 byte nonce
             this.state[14] = nonceView.getUint32(0, true);
             this.state[15] = nonceView.getUint32(4, true);
        }
    }

    private coreRound(state: Uint32Array): void {
        // Column rounds
        state[0] += state[4]; state[12] = rotr32(state[12] ^ state[0], 16);
        state[1] += state[5]; state[13] = rotr32(state[13] ^ state[1], 16);
        state[2] += state[6]; state[14] = rotr32(state[14] ^ state[2], 16);
        state[3] += state[7]; state[15] = rotr32(state[15] ^ state[3], 16);

        state[8] += state[12]; state[4] = rotr32(state[4] ^ state[8], 12);
        state[9] += state[13]; state[5] = rotr32(state[5] ^ state[9], 12);
        state[10] += state[14]; state[6] = rotr32(state[6] ^ state[10], 12);
        state[11] += state[15]; state[7] = rotr32(state[7] ^ state[11], 12);

        state[0] += state[4]; state[12] = rotr32(state[12] ^ state[0], 8);
        state[1] += state[5]; state[13] = rotr32(state[13] ^ state[1], 8);
        state[2] += state[6]; state[14] = rotr32(state[14] ^ state[2], 8);
        state[3] += state[7]; state[15] = rotr32(state[15] ^ state[3], 8);

        state[8] += state[12]; state[4] = rotr32(state[4] ^ state[8], 7);
        state[9] += state[13]; state[5] = rotr32(state[5] ^ state[9], 7);
        state[10] += state[14]; state[6] = rotr32(state[6] ^ state[10], 7);
        state[11] += state[15]; state[7] = rotr32(state[7] ^ state[11], 7);

        // Diagonal rounds
        state[0] += state[5]; state[15] = rotr32(state[15] ^ state[0], 16);
        state[1] += state[6]; state[12] = rotr32(state[12] ^ state[1], 16);
        state[2] += state[7]; state[13] = rotr32(state[13] ^ state[2], 16);
        state[3] += state[4]; state[14] = rotr32(state[14] ^ state[3], 16);

        state[10] += state[15]; state[5] = rotr32(state[5] ^ state[10], 12);
        state[11] += state[12]; state[6] = rotr32(state[6] ^ state[11], 12);
        state[8] += state[13]; state[7] = rotr32(state[7] ^ state[8], 12);
        state[9] += state[14]; state[4] = rotr32(state[4] ^ state[9], 12);

        state[0] += state[5]; state[15] = rotr32(state[15] ^ state[0], 8);
        state[1] += state[6]; state[12] = rotr32(state[12] ^ state[1], 8);
        state[2] += state[7]; state[13] = rotr32(state[13] ^ state[2], 8);
        state[3] += state[4]; state[14] = rotr32(state[14] ^ state[3], 8);

        state[10] += state[15]; state[5] = rotr32(state[5] ^ state[10], 7);
        state[11] += state[12]; state[6] = rotr32(state[6] ^ state[11], 7);
        state[8] += state[13]; state[7] = rotr32(state[7] ^ state[8], 7);
        state[9] += state[14]; state[4] = rotr32(state[4] ^ state[9], 7);

        // Ensure results are Uint32
        for(let i = 0; i < STATE_WORDS; i++) {
            state[i] = state[i] >>> 0;
        }
    }

    generate(results: Uint32Array): void {
        if (results.length !== BUF_WORDS) throw new Error("Results buffer must have size " + BUF_WORDS);

        const workingState = new Uint32Array(STATE_WORDS);
        const initial_state = new Uint32Array(this.state); // Keep original state for adding at the end

        for (let block = 0; block < BUF_BLOCKS; block++) {
            workingState.set(this.state);

            for (let i = 0; i < this.rounds; i++) {
                this.coreRound(workingState);
            }

            for (let i = 0; i < STATE_WORDS; i++) {
                 results[block * BLOCK_WORDS + i] = (workingState[i] + initial_state[i]) >>> 0;
            }

            // Increment counter (state[12] and state[13])
            this.state[12] = (this.state[12] + 1) >>> 0;
            if (this.state[12] === 0) {
                this.state[13] = (this.state[13] + 1) >>> 0;
            }
             // Update initial state for next block's addition step if needed (only counter changes)
            initial_state[12] = this.state[12];
            initial_state[13] = this.state[13];
        }
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
        newCore.state = new Uint32Array(this.state);
        newCore.rounds = this.rounds;
        return newCore;
    }
}


export class ChaChaRng {
    private core: ChaChaCore;
    private buffer: Uint32Array;
    private index: number;
    private rounds: number;

    private constructor(core: ChaChaCore, rounds: number) {
        this.core = core;
        this.buffer = new Uint32Array(BUF_WORDS);
        this.index = BUF_WORDS; // Force refill on first use
        this.rounds = rounds;
    }

    static fromSeed(seed: Uint8Array, rounds: 8 | 12 | 20): ChaChaRng {
         const core = new ChaChaCore(seed, new Uint8Array(8), rounds); // Default 8-byte zero nonce
         return new ChaChaRng(core, rounds);
    }

    private refill(): void {
        this.core.generate(this.buffer);
        this.index = 0;
    }

    nextU32(): number {
        if (this.index >= BUF_WORDS) {
            this.refill();
        }
        const val = this.buffer[this.index];
        this.index++;
        return val;
    }

    nextU64(): bigint {
        const low = BigInt(this.nextU32());
        const high = BigInt(this.nextU32());
        return (high << 32n) | low;
    }

    fillBytes(bytes: Uint8Array): void {
        let offset = 0;
        const len = bytes.length;
        while (offset < len) {
            if (this.index >= BUF_WORDS) {
                this.refill();
            }
            const remainingWords = BUF_WORDS - this.index;
            const remainingBufferBytes = remainingWords * 4;

            const bufferView = new DataView(this.buffer.buffer, this.buffer.byteOffset + this.index * 4);
            const bytesToCopy = Math.min(len - offset, remainingBufferBytes);

            for(let i = 0; i < bytesToCopy; ++i) {
                bytes[offset + i] = bufferView.getUint8(i);
            }

            this.index += Math.ceil(bytesToCopy / 4); // Advance index by words used
            offset += bytesToCopy;
        }
    }

     getWordPos(): bigint {
        const bufEndBlock = this.core.getBlockPos();
        const bufStartBlock = (bufEndBlock - BigInt(BUF_BLOCKS)) & U64_MASK; // Wrap subtraction

        const bufOffsetWords = BigInt(this.index);
        const blocksPart = bufOffsetWords / BigInt(BLOCK_WORDS);
        const wordsPart = bufOffsetWords % BigInt(BLOCK_WORDS);

        const posBlock = (bufStartBlock + blocksPart) & U64_MASK; // Wrap addition
        const posBlockWords = posBlock * BigInt(BLOCK_WORDS);

        // Combine block position (bits 4-67) and word offset (bits 0-3)
        // Result needs 68 bits, use BigInt
        return posBlockWords + wordsPart;
     }

    setWordPos(wordOffset: bigint): void {
        const block = wordOffset / BigInt(BLOCK_WORDS);
        const wordIndexInBlock = Number(wordOffset % BigInt(BLOCK_WORDS));

        this.core.setBlockPos(block);
        this.refill(); // Refill based on new block position
        this.index = wordIndexInBlock; // Set index within the newly generated buffer
    }

    setStream(stream: bigint): void {
        this.core.setNonce(stream);
        // Changing the stream requires regenerating the buffer, even if index != BUF_WORDS
        // Preserve the current absolute position
        const wp = this.getWordPos();
        this.setWordPos(wp); // This implicitly refills the buffer
    }

    getStream(): bigint {
        return this.core.getNonce();
    }

    getSeed(): Uint8Array {
        return this.core.getSeed();
    }

    clone(): ChaChaRng {
        const newRng = Object.create(ChaChaRng.prototype);
        newRng.core = this.core.clone();
        newRng.buffer = new Uint32Array(this.buffer);
        newRng.index = this.index;
        newRng.rounds = this.rounds;
        return newRng;
    }
}

export const ChaCha8Rng = (seed: Uint8Array) => ChaChaRng.fromSeed(seed, 8);
export const ChaCha12Rng = (seed: Uint8Array) => ChaChaRng.fromSeed(seed, 12);
export const ChaCha20Rng = (seed: Uint8Array) => ChaChaRng.fromSeed(seed, 20);
