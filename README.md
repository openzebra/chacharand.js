# chacharand.js

A pure JavaScript implementation of ChaCha8/12/20 cryptographically secure random number generators.

[![npm version](https://img.shields.io/npm/v/@hicaru/chacharand.js.svg)](https://www.npmjs.com/package/@hicaru/chacharand.js)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Overview

This library provides TypeScript/JavaScript implementations of the ChaCha family of random number generators (ChaCha8, ChaCha12, and ChaCha20). These are widely used, high-quality random number generators based on the ChaCha stream cipher developed by Daniel J. Bernstein.

ChaCha combines the core operations of the Salsa20 stream cipher with the improvements made in the ChaCha variant, resulting in a fast and secure pseudo-random number generator. The numbers (8/12/20) represent the number of rounds used in the algorithm, with more rounds providing increased security at the cost of performance.

## Installation

```bash
# Using npm
npm install @hicaru/chacharand.js

# Using yarn
yarn add @hicaru/chacharand.js

# Using pnpm
pnpm add @hicaru/chacharand.js
```

## Usage

### Basic Usage

```typescript
import { ChaCha8Rng, ChaCha12Rng, ChaCha20Rng } from '@hicaru/chacharand.js';

// Create a 32-byte seed
const seed = new Uint8Array(32);
// In a real application, you should use a cryptographically secure source to fill this seed
crypto.getRandomValues(seed);

// Create RNG instances
const rng8 = ChaCha8Rng(seed);   // Fastest, less secure
const rng12 = ChaCha12Rng(seed); // Balanced
const rng20 = ChaCha20Rng(seed); // Most secure, slower

// Generate random 32-bit integer
const randomInt = rng20.nextU32(); // Returns a number in range [0, 2^32-1]

// Generate random 64-bit integer
const randomBigInt = rng20.nextU64(); // Returns a BigInt in range [0, 2^64-1]

// Fill a buffer with random bytes
const buffer = new Uint8Array(64);
rng20.fillBytes(buffer);
```

### Advanced Usage

#### Cloning RNG State

You can clone the RNG state to get a new instance with the same state:

```typescript
// Create an RNG and generate some values
const rng = ChaCha20Rng(seed);
rng.nextU32();
rng.nextU64();

// Clone the RNG
const clonedRng = rng.clone();

// Both will generate the same sequence from this point
console.log(rng.nextU32() === clonedRng.nextU32()); // true
console.log(rng.nextU64() === clonedRng.nextU64()); // true
```

#### Streams and Position

You can manage different streams and positions in the random sequence:

```typescript
// Create an RNG
const rng = ChaCha20Rng(seed);

// Get the current stream
const currentStream = rng.getStream();

// Set a different stream (creates an independent sequence with the same seed)
rng.setStream(BigInt(42));

// Get and set the word position within the stream
const currentWordPos = rng.getWordPos();
rng.setWordPos(BigInt(1000)); // Skip to position 1000 in the sequence
```

#### Creating RNG from a Number Seed

If you want to create an RNG from a simple BigInt seed instead of a byte array:

```typescript
import { ChaChaRng } from '@hicaru/chacharand.js';

// Create an RNG from a 64-bit seed using ChaCha20
const rng = ChaChaRng.fromU64Seed(42n, 20);

// Same for ChaCha8 or ChaCha12
const rng8 = ChaChaRng.fromU64Seed(42n, 8);
const rng12 = ChaChaRng.fromU64Seed(42n, 12);
```

#### Serialization

You can save and restore the state of the RNG:

```typescript
// Create and use an RNG
const rng = ChaCha20Rng(seed);
rng.nextU32();
rng.nextU64();

// Get the state
const state = {
    seed: rng.getSeed(),
    stream: rng.getStream(),
    wordPos: rng.getWordPos()
};

// Save state as JSON
const jsonState = JSON.stringify(state);

// Later, restore the state
const parsedState = JSON.parse(jsonState);
const restoredRng = ChaCha20Rng(parsedState.seed);
restoredRng.setStream(BigInt(parsedState.stream));
restoredRng.setWordPos(BigInt(parsedState.wordPos));

// The restored RNG will continue from exactly where the original left off
```

## API Reference

### Functions

- `ChaCha8Rng(seed: Uint8Array)`: Creates a ChaCha8 RNG instance
- `ChaCha12Rng(seed: Uint8Array)`: Creates a ChaCha12 RNG instance
- `ChaCha20Rng(seed: Uint8Array)`: Creates a ChaCha20 RNG instance

### ChaChaRng Class

Static Methods:
- `ChaChaRng.fromSeed(seed: Uint8Array, rounds: 8 | 12 | 20)`: Creates a ChaCha RNG with specified rounds
- `ChaChaRng.fromU64Seed(state: bigint, rounds: 8 | 12 | 20)`: Creates a ChaCha RNG from a 64-bit seed

Instance Methods:
- `nextU32()`: Returns a random 32-bit unsigned integer (as a JavaScript number)
- `nextU64()`: Returns a random 64-bit unsigned integer (as a JavaScript BigInt)
- `fillBytes(bytes: Uint8Array)`: Fills the provided buffer with random bytes
- `getWordPos()`: Returns the current position in the random sequence (as a BigInt)
- `setWordPos(wordOffset: bigint)`: Sets the current position in the random sequence
- `getStream()`: Returns the current stream identifier (as a BigInt)
- `setStream(stream: bigint)`: Sets the stream identifier, creating an independent sequence
- `getSeed()`: Returns the seed as a Uint8Array
- `clone()`: Creates a copy of the RNG with the same state

## Implementation Notes

- The ChaCha algorithm uses a 16-word state (64 bytes) organized as a 4×4 matrix.
- The algorithm produces blocks of 64 bytes (16 words) of random data.
- This implementation maintains an internal buffer of 4 blocks (256 bytes) to improve performance.
- The state consists of:
  - A constant prefix (4 words)
  - The key/seed (8 words)
  - Block counter (2 words)
  - Nonce/stream identifier (2 words)

## Performance Considerations

- ChaCha8 is the fastest variant but provides less security.
- ChaCha12 offers a balance between performance and security.
- ChaCha20 provides the highest security but is slower.
- For most applications, ChaCha20 is recommended unless performance is critical.

## License

MIT
