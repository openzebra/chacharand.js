import { describe, it, expect } from 'vitest';
import { ChaCha8Rng, ChaCha12Rng, ChaCha20Rng, ChaChaRng } from '../';

describe('ChaCha Tests', () => {
    it('test_chacha_serde_roundtrip', () => {
        const seed = new Uint8Array([
            1, 0, 52, 0, 0, 0, 0, 0, 1, 0, 10, 0, 22, 32, 0, 0, 2, 0, 55, 49, 0, 11, 0, 0, 3, 0, 0,
            0, 0, 0, 2, 92,
        ]);

        let rng1_20 = ChaCha20Rng(seed);
        rng1_20.nextU32();
        rng1_20.nextU64();

        const state1_20 = {
            seed: rng1_20.getSeed(),
            stream: rng1_20.getStream(),
            wordPos: rng1_20.getWordPos(),
        };

        let decoded1_20 = ChaCha20Rng(seed);
        decoded1_20.setStream(state1_20.stream);
        decoded1_20.setWordPos(state1_20.wordPos);

        expect(decoded1_20.getSeed()).toEqual(rng1_20.getSeed());
        expect(decoded1_20.getStream()).toEqual(rng1_20.getStream());
        expect(decoded1_20.getWordPos()).toEqual(rng1_20.getWordPos());
        expect(rng1_20.nextU32()).toEqual(decoded1_20.nextU32());
        expect(rng1_20.nextU64()).toEqual(decoded1_20.nextU64());
        let rng1_12 = ChaCha12Rng(seed);
        rng1_12.nextU32();
        rng1_12.nextU64();
        const state1_12 = {
            seed: rng1_12.getSeed(),
            stream: rng1_12.getStream(),
            wordPos: rng1_12.getWordPos(),
        };
        let decoded1_12 = ChaCha12Rng(seed);
        decoded1_12.setStream(state1_12.stream);
        decoded1_12.setWordPos(state1_12.wordPos);
        expect(decoded1_12.getWordPos()).toEqual(rng1_12.getWordPos());
        expect(rng1_12.nextU32()).toEqual(decoded1_12.nextU32());
        expect(rng1_12.nextU64()).toEqual(decoded1_12.nextU64());

        let rng1_8 = ChaCha8Rng(seed);
        rng1_8.nextU32();
        rng1_8.nextU64();
        const state1_8 = {
            seed: rng1_8.getSeed(),
            stream: rng1_8.getStream(),
            wordPos: rng1_8.getWordPos(),
        };
        let decoded1_8 = ChaCha8Rng(seed);
        decoded1_8.setStream(state1_8.stream);
        decoded1_8.setWordPos(state1_8.wordPos);
        expect(decoded1_8.getWordPos()).toEqual(rng1_8.getWordPos());
        expect(rng1_8.nextU32()).toEqual(decoded1_8.nextU32());
        expect(rng1_8.nextU64()).toEqual(decoded1_8.nextU64());
    });

    it('test_chacha_serde_format_stability', () => {
        const j = `{"seed":[4,8,15,16,23,42,4,8,15,16,23,42,4,8,15,16,23,42,4,8,15,16,23,42,4,8,15,16,23,42,4,8],"stream":27182818284,"word_pos":314159265359}`;
        const r = Object.assign(Object.create(ChaCha20Rng(new Uint8Array(32)).constructor.prototype), JSON.parse(j));
        const j1 = JSON.stringify(r);
        expect(j).toBe(j1);
    });

    it('test_chacha_construction', () => {
        const seed = new Uint8Array([
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0,
            0, 0, 0,
        ]);
        const rng1 = ChaCha20Rng(seed);
        rng1.nextU32();
        const rng2 = rng1.clone();

        for (let i = 0; i < 10; i++) {
            expect(rng1.nextU32()).toBe(rng2.nextU32());
        }
    });

    it('test_chacha_true_values_a', () => {
        const seed = new Uint8Array(32);
        const rng = ChaCha20Rng(seed);
        const results = Array.from({ length: 16 }, () => rng.nextU32());
        const expected = [
            0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653, 0xb819d2bd, 0x1aed8da0, 0xccef36a8,
            0xc70d778b, 0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8, 0xf4b8436a, 0x1ca11815,
            0x69b687c3, 0x8665eeb2,
        ];
        expect(results).toEqual(expected);

        const results2 = Array.from({ length: 16 }, () => rng.nextU32());
        const expected2 = [
            0xbee7079f, 0x7a385155, 0x7c97ba98, 0x0d082d73, 0xa0290fcb, 0x6965e348, 0x3e53c612,
            0xed7aee32, 0x7621b729, 0x434ee69c, 0xb03371d5, 0xd539d874, 0x281fed31, 0x45fb0a51,
            0x1f0ae1ac, 0x6f4d794b,
        ];
        expect(results2).toEqual(expected2);
    });

    it('test_chacha_true_values_b', () => {
        const seed = new Uint8Array([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        const rng = ChaCha20Rng(seed);
        for (let i = 0; i < 16; i++) rng.nextU32();
        const results = Array.from({ length: 16 }, () => rng.nextU32());
        const expected = [
            0x2452eb3a, 0x9249f8ec, 0x8d829d9b, 0xddd4ceb1, 0xe8252083, 0x60818b01, 0xf38422b8,
            0x5aaa49c9, 0xbb00ca8e, 0xda3ba7b4, 0xc4b592d1, 0xfdf2732f, 0x4436274e, 0x2561b3c8,
            0xebdd4aa6, 0xa0136c00,
        ];
        expect(results).toEqual(expected);
    });

    it('test_chacha_true_values_c', () => {
        const seed = new Uint8Array([
            0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]);
        const expected = [
            0xfb4dd572, 0x4bc42ef1, 0xdf922636, 0x327f1394, 0xa78dea8f, 0x5e269039, 0xa1bebbc1,
            0xcaf09aae, 0xa25ab213, 0x48a6b46c, 0x1b9d9bcb, 0x092c5be6, 0x546ca624, 0x1bec45d5,
            0x87f47473, 0x96f0992e,
        ];
        const expectedEnd = 3 * 16;
        const results = Array.from({ length: 16 }, () => 0);

        const rng1 = ChaCha20Rng(seed);
        for (let i = 0; i < 32; i++) rng1.nextU32();
        for (let i = 0; i < 16; i++) results[i] = rng1.nextU32();
        expect(results).toEqual(expected);
        expect(rng1.getWordPos()).toBe(BigInt(expectedEnd));

        const rng2 = ChaCha20Rng(seed);
        rng2.setWordPos(BigInt(2 * 16));
        for (let i = 0; i < 16; i++) results[i] = rng2.nextU32();
        expect(results).toEqual(expected);
        expect(rng2.getWordPos()).toBe(BigInt(expectedEnd));

        const buf = new Uint8Array(32);
        rng2.fillBytes(buf);
        expect(rng2.getWordPos()).toBe(BigInt(expectedEnd + 8));
        rng2.fillBytes(buf.subarray(0, 25));
        expect(rng2.getWordPos()).toBe(BigInt(expectedEnd + 15));
        rng2.nextU64();
        expect(rng2.getWordPos()).toBe(BigInt(expectedEnd + 17));
        rng2.nextU32();
        rng2.nextU64();
        expect(rng2.getWordPos()).toBe(BigInt(expectedEnd + 20));
        rng2.fillBytes(buf.subarray(0, 1));
        expect(rng2.getWordPos()).toBe(BigInt(expectedEnd + 21));
    });

    it('test_chacha_multiple_blocks', () => {
        const seed = new Uint8Array([
            0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7,
            0, 0, 0,
        ]);
        const rng = ChaCha20Rng(seed);
        const results = Array.from({ length: 16 }, () => {
            const value = rng.nextU32();
            for (let i = 0; i < 16; i++) rng.nextU32();
            return value;
        });
        const expected = [
            0xf225c81a, 0x6ab1be57, 0x04d42951, 0x70858036, 0x49884684, 0x64efec72, 0x4be2d186,
            0x3615b384, 0x11cfa18e, 0xd3c50049, 0x75c775f6, 0x434c6530, 0x2c5bad8f, 0x898881dc,
            0x5f1c86d9, 0xc1f8e7f4,
        ];
        expect(results).toEqual(expected);
    });

    it('test_chacha_true_bytes', () => {
        const seed = new Uint8Array(32);
        const rng = ChaCha20Rng(seed);
        const results = new Uint8Array(32);
        rng.fillBytes(results);
        const expected = [
            118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189, 210,
            25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199,
        ];
        expect(Array.from(results)).toEqual(expected);
    });

    it('test_chacha_nonce', () => {
        const seed = new Uint8Array(32);
        const rng = ChaCha20Rng(seed);
        rng.setStream(BigInt(2) << BigInt(24 + 32));
        const results = Array.from({ length: 16 }, () => rng.nextU32());
        const expected = [
            0x374dc6c2, 0x3736d58c, 0xb904e24a, 0xcd3f93ef, 0x88228b1a, 0x96a4dfb3, 0x5b76ab72,
            0xc727ee54, 0x0e0e978a, 0xf3145c95, 0x1b748ea8, 0xf786c297, 0x99c28f5f, 0x628314e8,
            0x398a19fa, 0x6ded1b53,
        ];
        expect(results).toEqual(expected);
    });

    it('test_chacha_clone_streams', () => {
        const seed = new Uint8Array([
            0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7,
            0, 0, 0,
        ]);
        const rng = ChaCha20Rng(seed);
        const clone = rng.clone();
        for (let i = 0; i < 16; i++) expect(rng.nextU64()).toBe(clone.nextU64());
        rng.setStream(BigInt(51));
        for (let i = 0; i < 7; i++) expect(rng.nextU32()).not.toBe(clone.nextU32());
        clone.setStream(BigInt(51));
        for (let i = 7; i < 16; i++) expect(rng.nextU32()).toBe(clone.nextU32());
    });

    it('test_chacha_word_pos_wrap_exact', () => {
        const rng = ChaCha20Rng(new Uint8Array(32));
        const lastBlock = (BigInt(1) << BigInt(68)) - BigInt(4 * 16);
        rng.setWordPos(lastBlock);
        expect(rng.getWordPos()).toBe(lastBlock);
    });

    it('test_chacha_word_pos_wrap_excess', () => {
        const rng = ChaCha20Rng(new Uint8Array(32));
        const lastBlock = (BigInt(1) << BigInt(68)) - BigInt(16);
        rng.setWordPos(lastBlock);
        expect(rng.getWordPos()).toBe(lastBlock);
    });

    it('test_chacha_word_pos_zero', () => {
        const rng = ChaCha20Rng(new Uint8Array(32));
        expect(rng.getWordPos()).toBe(BigInt(0));
        rng.setWordPos(BigInt(0));
        expect(rng.getWordPos()).toBe(BigInt(0));
    });

    it('test_trait_objects', () => {
        const rng1 = ChaCha20Rng(new Uint8Array(32));
        const rng2 = rng1.clone();
        for (let i = 0; i < 1000; i++) expect(rng1.nextU64()).toBe(rng2.nextU64());
    });

    it('test_chacha_from_u64_seed', () => {
        const rng = ChaChaRng.fromU64Seed(42n, 20);
        expect(rng.nextU64()).toBe(9482535800248027256n);
    });

    it('test_chacha_from_seed_gen_range', () => {
        const rng = ChaChaRng.fromU64Seed(42n, 20);
        expect(rng.genRangeU64(0n, 1024n)).toBe(526n);
    });
});
 
