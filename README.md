# Zero Knowledge Proofs

A TypeScript implementation of a simplified zk-SNARK proof system using arithmetic circuits, R1CS constraints, and a Groth16-like prove/verify flow over BN128.

## Features

- Arithmetic circuit representation (addition and multiplication gates)
- R1CS constraint generation
- Simplified Groth16-like proving and verification
- CLI for proving knowledge of `a * b = c` without revealing `a` and `b`

## Usage

```bash
npm install
npx tsx src/cli.ts --a 3 --b 7
```

## Testing

```bash
npm test
```

## Structure

- `src/circuit.ts` — arithmetic circuit builder
- `src/r1cs.ts` — R1CS constraint system
- `src/prover.ts` — proof generation
- `src/verifier.ts` — proof verification
- `src/cli.ts` — command-line interface
