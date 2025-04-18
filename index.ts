const BLOCK_WORDS = 16;
const BUF_BLOCKS = 4;
const BUF_WORDS = BLOCK_WORDS * BUF_BLOCKS;

const STATE_WORDS = 16;

const U32_MASK = 0xffffffffn;

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
            this.state[13] = nonceView.getUint32(0, true);
            this.state[14] = nonceView.getUint32(4, true);
            this.state[15] = nonceView.getUint32(8, true);
            this.state[12] = 0;
        } else {
            this.state[14] = nonceView.getUint32(0, true);
            this.state[15] = nonceView.getUint32(4, true);
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
            for (let i = 0; i < STATE_WORDS; i++) {
                results[block * BLOCK_WORDS + i] = (workingState[i] + blockInputState[i]) >>> 0;
            }
            blockInputState[12] = (blockInputState[12] + 1) >>> 0;
            if (blockInputState[12] === 0) {
                blockInputState[13] = (blockInputState[13] + 1) >>> 0;
            }
        }
        this.state.set(blockInputState.subarray(12, 14), 12);
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
        const newStateBuffer = this.state.buffer.slice(0);
        newCore.state = new Uint32Array(newStateBuffer);
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
        this.index = BUF_WORDS;
        this.rounds = rounds;
    }

    static fromSeed(seed: Uint8Array, rounds: 8 | 12 | 20): ChaChaRng {
        const core = new ChaChaCore(seed, new Uint8Array(8), rounds);
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
        const len = bytes.length;
        const byteView = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        let offset = 0;
        while (offset < len) {
            if (this.index >= BUF_WORDS) {
                this.refill();
            }
            const bufferRemainingWords = BUF_WORDS - this.index;
            const bufferRemainingBytes = bufferRemainingWords * 4;
            const bytesToCopy = Math.min(len - offset, bufferRemainingBytes);
            const internalBufferView = new DataView(this.buffer.buffer, this.buffer.byteOffset + this.index * 4);
            for (let i = 0; i < bytesToCopy; i++) {
                byteView.setUint8(offset + i, internalBufferView.getUint8(i));
            }
            this.index += Math.ceil(bytesToCopy / 4);
            offset += bytesToCopy;
        }
    }

    getWordPos(): bigint {
        const bufEndBlock = this.core.getBlockPos();
        const bufStartBlock = (bufEndBlock - BigInt(BUF_BLOCKS)) & ((1n << 64n) - 1n);
        const bufOffsetWords = BigInt(this.index);
        const blocksConsumed = bufOffsetWords / BigInt(BLOCK_WORDS);
        const wordsConsumedInBlock = bufOffsetWords % BigInt(BLOCK_WORDS);
        const currentBlock = (bufStartBlock + blocksConsumed) & ((1n << 64n) - 1n);
        const currentWordPos = (currentBlock * BigInt(BLOCK_WORDS)) + wordsConsumedInBlock;

        return currentWordPos;
    }

    setWordPos(wordOffset: bigint): void {
        const targetBlock = wordOffset / BigInt(BLOCK_WORDS);
        const wordIndexInBlock = Number(wordOffset % BigInt(BLOCK_WORDS));
        this.core.setBlockPos(targetBlock);
        this.refill();
        this.index = Math.min(Math.max(wordIndexInBlock, 0), BUF_WORDS - 1);
    }

    setStream(stream: bigint): void {
        this.core.setNonce(stream);
        const wp = this.getWordPos();
        this.setWordPos(wp);
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
