#!/usr/bin/env node

/**
 * CLI for the zero-knowledge proof system.
 *
 * Commands:
 *   prove  <a> <b>   - Generate a proof that you know a and b such that a * b = c
 *   verify <c>       - Verify a proof (reads proof from stdin or file)
 *   demo   <a> <b>   - Run full prove-and-verify cycle
 */

import { buildMultiplicationCircuit } from "./circuit.js";
import { circuitToR1CS, verifyR1CS } from "./r1cs.js";
import {
  trustedSetup,
  prove,
  buildWitness,
  FIELD_ORDER,
} from "./prover.js";
import { verify, serializeProof } from "./verifier.js";
import { bn254 } from "@noble/curves/bn254";

const Fr = bn254.fields.Fr;

export function printUsage(): void {
  console.log(`
Zero-Knowledge Proof CLI
========================

Prove knowledge of a and b such that a * b = c, without revealing a or b.

Usage:
  npx ts-node --esm src/cli.ts demo <a> <b>     Full prove-and-verify demo
  npx ts-node --esm src/cli.ts prove <a> <b>     Generate proof
  npx ts-node --esm src/cli.ts verify <c> <proof> Verify proof JSON

Examples:
  npx ts-node --esm src/cli.ts demo 3 7
  npx ts-node --esm src/cli.ts demo 42 1337
`);
}

export function runDemo(aStr: string, bStr: string): void {
  const a = BigInt(aStr);
  const b = BigInt(bStr);
  const c = Fr.mul(a, b);

  console.log("=== Zero-Knowledge Proof: a * b = c ===\n");
  console.log(`Private inputs: a = ${a}, b = ${b}`);
  console.log(`Public output:  c = ${c}`);
  console.log(`Field order:    ${FIELD_ORDER}\n`);

  // Step 1: Build circuit
  console.log("Step 1: Building arithmetic circuit...");
  const circuit = buildMultiplicationCircuit();
  console.log(
    `  Circuit: ${circuit.gates.length} gate(s), ${circuit.numWires} wire(s)`
  );
  console.log(
    `  Gate: wire[${circuit.gates[0].leftInput}] * wire[${circuit.gates[0].rightInput}] = wire[${circuit.gates[0].output}]\n`
  );

  // Step 2: Convert to R1CS
  console.log("Step 2: Converting to R1CS constraints...");
  const r1cs = circuitToR1CS(circuit);
  console.log(`  ${r1cs.numConstraints} constraint(s) generated`);

  // Step 3: Build witness
  console.log("\nStep 3: Building witness...");
  const witness = buildWitness(a, b);
  console.log(`  Witness: [${witness.map((w) => w.toString()).join(", ")}]`);

  // Verify R1CS satisfaction
  const r1csSatisfied = verifyR1CS(r1cs, witness, FIELD_ORDER);
  console.log(`  R1CS satisfied: ${r1csSatisfied}`);
  if (!r1csSatisfied) {
    console.error("ERROR: Witness does not satisfy R1CS constraints!");
    process.exit(1);
  }

  // Step 4: Trusted setup
  console.log("\nStep 4: Performing trusted setup...");
  const startSetup = performance.now();
  const { provingKey, verificationKey } = trustedSetup(r1cs);
  const setupTime = (performance.now() - startSetup).toFixed(1);
  console.log(`  Setup completed in ${setupTime}ms`);

  // Step 5: Generate proof
  console.log("\nStep 5: Generating proof...");
  const startProve = performance.now();
  const proof = prove(r1cs, provingKey, witness);
  const proveTime = (performance.now() - startProve).toFixed(1);
  console.log(`  Proof generated in ${proveTime}ms`);

  const serialized = serializeProof(proof);
  console.log(`  piA: (${serialized.piA.x.slice(0, 20)}..., ${serialized.piA.y.slice(0, 20)}...)`);
  console.log(`  piB: (${serialized.piB.x.c0.slice(0, 20)}..., ...)`);
  console.log(`  piC: (${serialized.piC.x.slice(0, 20)}..., ${serialized.piC.y.slice(0, 20)}...)`);

  // Step 6: Verify proof
  console.log("\nStep 6: Verifying proof...");
  console.log(`  Public input: c = ${c}`);
  console.log("  (a and b are NOT revealed to the verifier)\n");
  const startVerify = performance.now();
  const isValid = verify(verificationKey, proof, [c]);
  const verifyTime = (performance.now() - startVerify).toFixed(1);

  console.log(`  Verification result: ${isValid ? "VALID" : "INVALID"}`);
  console.log(`  Verified in ${verifyTime}ms`);

  if (isValid) {
    console.log(
      "\n  The verifier is convinced that the prover knows a and b"
    );
    console.log("  such that a * b = c, without learning a or b.");
  }

  // Step 7: Demonstrate soundness - try a fake proof
  console.log("\n--- Soundness Check ---");
  console.log("Attempting to verify with wrong public input (c + 1)...");
  const fakeResult = verify(verificationKey, proof, [c + 1n]);
  console.log(
    `  Verification with wrong input: ${fakeResult ? "VALID (BAD!)" : "INVALID (expected)"}`
  );
}

export function runProve(aStr: string, bStr: string): void {
  const a = BigInt(aStr);
  const b = BigInt(bStr);
  const c = Fr.mul(a, b);

  const circuit = buildMultiplicationCircuit();
  const r1cs = circuitToR1CS(circuit);
  const witness = buildWitness(a, b);
  const { provingKey, verificationKey } = trustedSetup(r1cs);
  const proof = prove(r1cs, provingKey, witness);
  const serialized = serializeProof(proof);

  // Output proof and verification key as JSON
  const output = {
    publicInput: c.toString(),
    proof: serialized,
    // In a real system, the VK would be published separately
  };

  console.log(JSON.stringify(output, null, 2));
}

/** Parse CLI arguments and dispatch to the appropriate command. */
export function main(argv: string[] = process.argv.slice(2)): void {
  const command = argv[0];

  switch (command) {
    case "demo":
      if (argv.length < 3) {
        console.error("Usage: demo <a> <b>");
        process.exit(1);
      }
      runDemo(argv[1], argv[2]);
      break;

    case "prove":
      if (argv.length < 3) {
        console.error("Usage: prove <a> <b>");
        process.exit(1);
      }
      runProve(argv[1], argv[2]);
      break;

    case "help":
    case "--help":
    case "-h":
      printUsage();
      break;

    default:
      if (argv.length >= 2) {
        // Default to demo mode if two numbers are provided
        runDemo(argv[0], argv[1]);
      } else {
        printUsage();
      }
      break;
  }
}

// Run when executed directly (not when imported as a module)
const isDirectExecution =
  typeof process !== "undefined" &&
  process.argv[1] &&
  (process.argv[1].endsWith("cli.ts") || process.argv[1].endsWith("cli.js"));

if (isDirectExecution) {
  main();
}
