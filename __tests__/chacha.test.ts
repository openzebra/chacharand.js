import { describe, it, expect } from 'vitest';
import { ChaCha8Rng, ChaCha12Rng, ChaCha20Rng } from '../';

const seed32 = (val: number = 0): Uint8Array => new Uint8Array(32).fill(val);

describe('ChaChaRng', () => {
    it('test_chacha_construction', () => {
        const seed = new Uint8Array([
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0,
            0, 0, 0,
        ]);
        let rng1 = ChaCha20Rng(seed);
        expect(rng1.nextU32()).toBe(137206642);

        const seed2 = new Uint8Array(32);
        rng1.fillBytes(seed2);
        let rng2 = ChaCha20Rng(seed2);
         expect(rng2.nextU32()).toBeGreaterThan(0);
    });

    it('test_chacha_true_values_a (RFC Draft Vector 1 & 2)', () => {
        const seed = seed32(0);
        let rng = ChaCha20Rng(seed);

        const results1 = new Uint32Array(16);
        for (let i = 0; i < 16; i++) results1[i] = rng.nextU32();
        const expected1 = [
            0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653, 0xb819d2bd, 0x1aed8da0, 0xccef36a8,
            0xc70d778b, 0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8, 0xf4b8436a, 0x1ca11815,
            0x69b687c3, 0x8665eeb2,
        ];
        expect(Array.from(results1)).toEqual(expected1);

        const results2 = new Uint32Array(16);
        for (let i = 0; i < 16; i++) results2[i] = rng.nextU32();
        const expected2 = [
            0xbee7079f, 0x7a385155, 0x7c97ba98, 0x0d082d73, 0xa0290fcb, 0x6965e348, 0x3e53c612,
            0xed7aee32, 0x7621b729, 0x434ee69c, 0xb03371d5, 0xd539d874, 0x281fed31, 0x45fb0a51,
            0x1f0ae1ac, 0x6f4d794b,
        ];
        expect(Array.from(results2)).toEqual(expected2);
    });

     it('test_chacha_true_values_b (RFC Draft Vector 3)', () => {
        const seed = new Uint8Array([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        let rng = ChaCha20Rng(seed);

        for (let i = 0; i < 16; i++) rng.nextU32();

        const results = new Uint32Array(16);
        for (let i = 0; i < 16; i++) results[i] = rng.nextU32();
        const expected = [
            0x2452eb3a, 0x9249f8ec, 0x8d829d9b, 0xddd4ceb1, 0xe8252083, 0x60818b01, 0xf38422b8,
            0x5aaa49c9, 0xbb00ca8e, 0xda3ba7b4, 0xc4b592d1, 0xfdf2732f, 0x4436274e, 0x2561b3c8,
            0xebdd4aa6, 0xa0136c00,
        ];
        expect(Array.from(results)).toEqual(expected);
    });

    it('test_chacha_true_values_c (RFC Draft Vector 4) & Seeking', () => {
        const seed = new Uint8Array([
            0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]);
        const expected = [
            0xfb4dd572, 0x4bc42ef1, 0xdf922636, 0x327f1394, 0xa78dea8f, 0x5e269039, 0xa1bebbc1,
            0xcaf09aae, 0xa25ab213, 0x48a6b46c, 0x1b9d9bcb, 0x092c5be6, 0x546ca624, 0x1bec45d5,
            0x87f47473, 0x96f0992e,
        ];
        const expected_end = 3n * 16n; 
        const results = new Uint32Array(16);

        let rng1 = ChaCha20Rng(seed);
        for (let i = 0; i < 32; i++) rng1.nextU32(); 
        for (let i = 0; i < 16; i++) results[i] = rng1.nextU32();
        expect(Array.from(results)).toEqual(expected);
        expect(rng1.getWordPos()).toBe(expected_end);

        let rng2 = ChaCha20Rng(seed);
        rng2.setWordPos(2n * 16n); 
        for (let i = 0; i < 16; i++) results[i] = rng2.nextU32();
        expect(Array.from(results)).toEqual(expected);
        expect(rng2.getWordPos()).toBe(expected_end);

        let buf = new Uint8Array(32);
        rng2.fillBytes(buf); 
        expect(rng2.getWordPos()).toBe(expected_end + 8n);
        rng2.fillBytes(buf.subarray(0, 25)); 
        expect(rng2.getWordPos()).toBe(expected_end + 8n + 7n);
        rng2.nextU64(); 
        expect(rng2.getWordPos()).toBe(expected_end + 8n + 7n + 2n);
        rng2.nextU32(); 
        rng2.nextU64(); 
        expect(rng2.getWordPos()).toBe(expected_end + 8n + 7n + 2n + 1n + 2n);
        rng2.fillBytes(buf.subarray(0, 1)); 
        expect(rng2.getWordPos()).toBe(expected_end + 8n + 7n + 2n + 1n + 2n + 1n); 
    });


    it('test_chacha_multiple_blocks', () => {
        const seed = new Uint8Array([
            0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7,
            0, 0, 0,
        ]);
        let rng = ChaCha20Rng(seed);

        const results = new Uint32Array(16);
        for (let i = 0; i < 16; i++) {
            results[i] = rng.nextU32(); 
            for (let j = 0; j < 16; j++) { 
                rng.nextU32();
            }
        }
        const expected = [
            0xf225c81a, 0x6ab1be57, 0x04d42951, 0x70858036, 0x49884684, 0x64efec72, 0x4be2d186,
            0x3615b384, 0x11cfa18e, 0xd3c50049, 0x75c775f6, 0x434c6530, 0x2c5bad8f, 0x898881dc,
            0x5f1c86d9, 0xc1f8e7f4,
        ];
        
        rng = ChaCha20Rng(seed); 
        const resultsRustLogic = new Uint32Array(16);
        for (let i = 0; i < 16; i++) {
             rng.setWordPos(BigInt(i) * 16n + BigInt(i));
             resultsRustLogic[i] = rng.nextU32();
        }
         expect(Array.from(resultsRustLogic)).toEqual(expected);


    });

    it('test_chacha_true_bytes', () => {
        const seed = seed32(0);
        let rng = ChaCha20Rng(seed);
        const results = new Uint8Array(32);
        rng.fillBytes(results);
        const expected = [
            118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189, 210,
            25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199,
        ];
        expect(Array.from(results)).toEqual(expected);
    });

    it('test_chacha_nonce (RFC Draft Vector 5)', () => {
        const seed = seed32(0);
        let rng = ChaCha20Rng(seed);
        rng.setStream(2n << 56n); 

        const results = new Uint32Array(16);
        for (let i = 0; i < 16; i++) results[i] = rng.nextU32();
        const expected = [
            0x374dc6c2, 0x3736d58c, 0xb904e24a, 0xcd3f93ef, 0x88228b1a, 0x96a4dfb3, 0x5b76ab72,
            0xc727ee54, 0x0e0e978a, 0xf3145c95, 0x1b748ea8, 0xf786c297, 0x99c28f5f, 0x628314e8,
            0x398a19fa, 0x6ded1b53,
        ];
        expect(Array.from(results)).toEqual(expected);
    });

    it('test_chacha_clone_streams', () => {
        const seed = new Uint8Array([
            0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7,
            0, 0, 0,
        ]);
        let rng = ChaCha20Rng(seed);
        let clone = rng.clone();
        for (let i = 0; i < 16; i++) {
            expect(rng.nextU64()).toEqual(clone.nextU64());
        }

        rng.setStream(51n);
        for (let i = 0; i < 7; i++) { 
            expect(rng.nextU32()).not.toEqual(clone.nextU32());
        }
        clone.setStream(51n); 
        for (let i = 7; i < 16; i++) { 
            expect(rng.nextU32()).toEqual(clone.nextU32());
        }
         for (let i = 0; i < 16; i++) {
            expect(rng.nextU64()).toEqual(clone.nextU64());
        }
    });

    it('test_chacha_word_pos_wrap_exact', () => {
        let rng = ChaCha20Rng(seed32());
        const last_block_pos = (1n << 68n) - 64n;
        rng.setWordPos(last_block_pos);
        expect(rng.getWordPos()).toBe(last_block_pos);
        for(let i = 0; i < 64; i++) rng.nextU32();
        expect(rng.getWordPos()).toBe(0n); // Should wrap to 0 after consuming 64 words
    });

     it('test_chacha_word_pos_wrap_excess', () => {
        let rng = ChaCha20Rng(seed32());
        const near_wrap_pos = (1n << 68n) - 1n;
        rng.setWordPos(near_wrap_pos);
        expect(rng.getWordPos()).toBe(near_wrap_pos);
    });


    it('test_chacha_word_pos_zero', () => {
        let rng = ChaCha20Rng(seed32());
        expect(rng.getWordPos()).toBe(0n);
        rng.setWordPos(0n);
        expect(rng.getWordPos()).toBe(0n);
        rng.nextU32();
        expect(rng.getWordPos()).toBe(1n);
        rng.setWordPos(0n);
        expect(rng.getWordPos()).toBe(0n);
    });

     it('test different rounds', () => {
        const seed = seed32(1);
        let rng8 = ChaCha8Rng(seed);
        let rng12 = ChaCha12Rng(seed);
        let rng20 = ChaCha20Rng(seed);

        const val8 = rng8.nextU32();
        const val12 = rng12.nextU32();
        const val20 = rng20.nextU32();

        expect(val8).not.toEqual(val12);
        expect(val12).not.toEqual(val20);
        expect(val8).not.toEqual(val20);

        rng8.setWordPos(100n);
        rng12.setWordPos(100n);
        rng20.setWordPos(100n);

        const val8_seek = rng8.nextU32();
        const val12_seek = rng12.nextU32();
        const val20_seek = rng20.nextU32();

        expect(val8_seek).not.toEqual(val12_seek);
        expect(val12_seek).not.toEqual(val20_seek);
        expect(val8_seek).not.toEqual(val20_seek);

        expect(val8_seek).not.toEqual(val8);
        expect(val12_seek).not.toEqual(val12);
        expect(val20_seek).not.toEqual(val20);
     });

});
 
