import { describe, it, expect } from "vitest";
import { bn254 } from "@noble/curves/bn254";
import {
  buildMultiplicationCircuit,
  evaluateCircuit,
} from "./circuit.js";
import { circuitToR1CS, verifyR1CS } from "./r1cs.js";
import {
  trustedSetup,
  prove,
  buildWitness,
  FIELD_ORDER,
} from "./prover.js";
import { verify } from "./verifier.js";

const Fr = bn254.fields.Fr;

describe("Circuit", () => {
  it("should build a multiplication circuit with correct structure", () => {
    const circuit = buildMultiplicationCircuit();

    expect(circuit.numWires).toBe(4);
    expect(circuit.numPublicInputs).toBe(1);
    expect(circuit.numPrivateInputs).toBe(2);
    expect(circuit.gates).toHaveLength(1);
    expect(circuit.gates[0].type).toBe("mul");
  });

  it("should evaluate a * b = c correctly", () => {
    const circuit = buildMultiplicationCircuit();
    const a = 3n;
    const b = 7n;
    const c = Fr.mul(a, b);
    const witness = [1n, c, a, b];

    expect(evaluateCircuit(circuit, witness, FIELD_ORDER)).toBe(true);
  });

  it("should reject incorrect witness", () => {
    const circuit = buildMultiplicationCircuit();
    const witness = [1n, 42n, 3n, 7n]; // 3 * 7 != 42

    expect(evaluateCircuit(circuit, witness, FIELD_ORDER)).toBe(false);
  });

  it("should reject witness with wrong length", () => {
    const circuit = buildMultiplicationCircuit();
    expect(() => evaluateCircuit(circuit, [1n, 2n], FIELD_ORDER)).toThrow();
  });
});

describe("R1CS", () => {
  it("should convert multiplication circuit to R1CS", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    expect(r1cs.numConstraints).toBe(1);
    expect(r1cs.numWires).toBe(4);

    // Check that the constraint selects correct wires
    const constraint = r1cs.constraints[0];
    expect(constraint.a).toEqual([[2, 1n]]); // wire 2 (a)
    expect(constraint.b).toEqual([[3, 1n]]); // wire 3 (b)
    expect(constraint.c).toEqual([[1, 1n]]); // wire 1 (c)
  });

  it("should verify R1CS with valid witness", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    const a = 5n;
    const b = 11n;
    const witness = buildWitness(a, b);

    expect(verifyR1CS(r1cs, witness, FIELD_ORDER)).toBe(true);
  });

  it("should reject R1CS with invalid witness", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    // Wrong product
    const witness = [1n, 99n, 5n, 11n];
    expect(verifyR1CS(r1cs, witness, FIELD_ORDER)).toBe(false);
  });
});

describe("Prover and Verifier", () => {
  it("should generate and verify a valid proof for 3 * 7 = 21", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    const a = 3n;
    const b = 7n;
    const witness = buildWitness(a, b);
    const c = witness[1];

    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);
    const isValid = verify(verificationKey, proof, [c]);

    expect(isValid).toBe(true);
  });

  it("should generate and verify a valid proof for large numbers", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    const a = 123456789n;
    const b = 987654321n;
    const witness = buildWitness(a, b);
    const c = witness[1];

    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);
    const isValid = verify(verificationKey, proof, [c]);

    expect(isValid).toBe(true);
  });

  it("should reject proof with wrong public input", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    const a = 3n;
    const b = 7n;
    const witness = buildWitness(a, b);
    const c = witness[1];

    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);

    // Verify with wrong c
    const isValid = verify(verificationKey, proof, [c + 1n]);
    expect(isValid).toBe(false);
  });

  it("should build correct witness", () => {
    const witness = buildWitness(4n, 5n);

    expect(witness[0]).toBe(1n); // constant
    expect(witness[1]).toBe(20n); // c = 4 * 5
    expect(witness[2]).toBe(4n); // a
    expect(witness[3]).toBe(5n); // b
  });
});
