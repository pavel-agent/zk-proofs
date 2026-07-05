import { describe, it, expect } from "vitest";
import { bn254 } from "@noble/curves/bn254";
import {
  buildMultiplicationCircuit,
  evaluateCircuit,
  type Circuit,
  type Gate,
} from "./circuit.js";
import {
  circuitToR1CS,
  verifyR1CS,
  evalSparse,
  type SparseVector,
  type R1CSConstraint,
} from "./r1cs.js";
import {
  trustedSetup,
  prove,
  buildWitness,
  FIELD_ORDER,
} from "./prover.js";
import { verify, serializeProof, deserializeProof } from "./verifier.js";

const Fr = bn254.fields.Fr;
const G1 = bn254.G1;

// ---------------------------------------------------------------------------
// Field arithmetic (Fr) tests
// ---------------------------------------------------------------------------

describe("Field arithmetic (BN254 Fr)", () => {
  it("should add two elements modulo the field order", () => {
    expect(Fr.add(3n, 7n)).toBe(10n);
    expect(Fr.add(0n, 0n)).toBe(0n);
    expect(Fr.add(FIELD_ORDER - 1n, 1n)).toBe(0n); // wrap around
  });

  it("should multiply two elements modulo the field order", () => {
    expect(Fr.mul(3n, 7n)).toBe(21n);
    expect(Fr.mul(0n, 12345n)).toBe(0n);
    expect(Fr.mul(1n, 42n)).toBe(42n);
  });

  it("should compute modular inverse correctly", () => {
    const a = 7n;
    const aInv = Fr.inv(a);
    expect(Fr.mul(a, aInv)).toBe(1n);
  });

  it("should compute inverse of large field elements", () => {
    const a = FIELD_ORDER - 2n;
    const aInv = Fr.inv(a);
    expect(Fr.mul(a, aInv)).toBe(1n);
  });

  it("should throw on inverse of zero", () => {
    expect(() => Fr.inv(0n)).toThrow();
  });

  it("should subtract elements correctly", () => {
    expect(Fr.sub(10n, 3n)).toBe(7n);
    // Subtraction wrapping: 3 - 10 = FIELD_ORDER - 7
    expect(Fr.sub(3n, 10n)).toBe(FIELD_ORDER - 7n);
  });

  it("should exponentiate correctly", () => {
    expect(Fr.pow(2n, 10n)).toBe(1024n);
    expect(Fr.pow(3n, 0n)).toBe(1n);
    expect(Fr.pow(0n, 5n)).toBe(0n);
  });

  it("should negate elements correctly", () => {
    const a = 42n;
    const neg = Fr.neg(a);
    expect(Fr.add(a, neg)).toBe(0n);
  });

  it("should handle FIELD_ORDER as zero", () => {
    // FIELD_ORDER mod FIELD_ORDER = 0
    expect(Fr.add(FIELD_ORDER, 0n)).toBe(0n);
  });
});

// ---------------------------------------------------------------------------
// Elliptic curve (BN128/BN254) point tests
// ---------------------------------------------------------------------------

describe("BN254 elliptic curve points", () => {
  it("should have a valid generator point (G1)", () => {
    const base = G1.ProjectivePoint.BASE;
    // The base point should not be the identity
    expect(base.equals(G1.ProjectivePoint.ZERO)).toBe(false);
  });

  it("should satisfy the group law: P + ZERO = P", () => {
    const P = G1.ProjectivePoint.BASE;
    const result = P.add(G1.ProjectivePoint.ZERO);
    expect(result.equals(P)).toBe(true);
  });

  it("should satisfy the group law: P + (-P) = ZERO", () => {
    const P = G1.ProjectivePoint.BASE;
    const negP = P.negate();
    const result = P.add(negP);
    expect(result.equals(G1.ProjectivePoint.ZERO)).toBe(true);
  });

  it("should satisfy scalar multiplication: 1 * G = G", () => {
    const G = G1.ProjectivePoint.BASE;
    const result = G.multiply(1n);
    expect(result.equals(G)).toBe(true);
  });

  it("should satisfy scalar multiplication: 2 * G = G + G", () => {
    const G = G1.ProjectivePoint.BASE;
    const doubled = G.multiply(2n);
    const added = G.add(G);
    expect(doubled.equals(added)).toBe(true);
  });

  it("should satisfy scalar multiplication associativity: a*(b*G) = (a*b)*G", () => {
    const G = G1.ProjectivePoint.BASE;
    const a = 5n;
    const b = 7n;
    const left = G.multiply(b).multiply(a);
    const right = G.multiply(Fr.mul(a, b));
    expect(left.equals(right)).toBe(true);
  });

  it("should satisfy distributivity: (a+b)*G = a*G + b*G", () => {
    const G = G1.ProjectivePoint.BASE;
    const a = 13n;
    const b = 17n;
    const left = G.multiply(Fr.add(a, b));
    const right = G.multiply(a).add(G.multiply(b));
    expect(left.equals(right)).toBe(true);
  });

  it("should have the correct scalar field order", () => {
    // n * G = ZERO (the generator has order n)
    // We can't practically compute this, but we can verify the order is prime and > 0
    expect(FIELD_ORDER > 0n).toBe(true);
    // BN254 scalar field order is well-known
    expect(FIELD_ORDER).toBe(
      21888242871839275222246405745257275088548364400416034343698204186575808495617n
    );
  });

  it("should round-trip G1 points via affine coordinates", () => {
    const P = G1.ProjectivePoint.BASE.multiply(42n);
    const aff = P.toAffine();
    const restored = G1.ProjectivePoint.fromAffine({ x: aff.x, y: aff.y });
    expect(restored.equals(P)).toBe(true);
  });

  it("should round-trip G2 points via affine coordinates", () => {
    const G2 = bn254.G2;
    const P = G2.ProjectivePoint.BASE.multiply(42n);
    const aff = P.toAffine();
    const restored = G2.ProjectivePoint.fromAffine(aff);
    expect(restored.equals(P)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Circuit building and evaluation tests
// ---------------------------------------------------------------------------

describe("Circuit", () => {
  it("should build a multiplication circuit with correct structure", () => {
    const circuit = buildMultiplicationCircuit();

    expect(circuit.numWires).toBe(4);
    expect(circuit.numPublicInputs).toBe(1);
    expect(circuit.numPrivateInputs).toBe(2);
    expect(circuit.gates).toHaveLength(1);
    expect(circuit.gates[0].type).toBe("mul");
  });

  it("should have the correct wire layout", () => {
    const circuit = buildMultiplicationCircuit();
    const gate = circuit.gates[0];

    // wire 0 = constant 1, wire 1 = public output c, wire 2 = a, wire 3 = b
    expect(gate.leftInput).toBe(2);
    expect(gate.rightInput).toBe(3);
    expect(gate.output).toBe(1);
  });

  it("should evaluate a * b = c correctly", () => {
    const circuit = buildMultiplicationCircuit();
    const a = 3n;
    const b = 7n;
    const c = Fr.mul(a, b);
    const witness = [1n, c, a, b];

    expect(evaluateCircuit(circuit, witness, FIELD_ORDER)).toBe(true);
  });

  it("should evaluate with large numbers", () => {
    const circuit = buildMultiplicationCircuit();
    const a = 999999999999n;
    const b = 888888888888n;
    const c = Fr.mul(a, b);
    const witness = [1n, c, a, b];

    expect(evaluateCircuit(circuit, witness, FIELD_ORDER)).toBe(true);
  });

  it("should evaluate correctly when result wraps around field order", () => {
    const circuit = buildMultiplicationCircuit();
    // Use values whose product exceeds FIELD_ORDER
    const a = FIELD_ORDER - 1n; // equivalent to -1 in the field
    const b = 2n;
    const c = Fr.mul(a, b); // (-1) * 2 = -2 = FIELD_ORDER - 2
    const witness = [1n, c, a, b];

    expect(evaluateCircuit(circuit, witness, FIELD_ORDER)).toBe(true);
    expect(c).toBe(FIELD_ORDER - 2n);
  });

  it("should evaluate with a = 1 (identity)", () => {
    const circuit = buildMultiplicationCircuit();
    const a = 1n;
    const b = 42n;
    const c = Fr.mul(a, b);
    const witness = [1n, c, a, b];

    expect(evaluateCircuit(circuit, witness, FIELD_ORDER)).toBe(true);
    expect(c).toBe(42n);
  });

  it("should evaluate with a = 0", () => {
    const circuit = buildMultiplicationCircuit();
    const a = 0n;
    const b = 42n;
    const c = Fr.mul(a, b);
    const witness = [1n, c, a, b];

    expect(evaluateCircuit(circuit, witness, FIELD_ORDER)).toBe(true);
    expect(c).toBe(0n);
  });

  it("should reject incorrect witness", () => {
    const circuit = buildMultiplicationCircuit();
    const witness = [1n, 42n, 3n, 7n]; // 3 * 7 != 42

    expect(evaluateCircuit(circuit, witness, FIELD_ORDER)).toBe(false);
  });

  it("should reject witness with wrong length (too short)", () => {
    const circuit = buildMultiplicationCircuit();
    expect(() => evaluateCircuit(circuit, [1n, 2n], FIELD_ORDER)).toThrow(
      /Witness length/
    );
  });

  it("should reject witness with wrong length (too long)", () => {
    const circuit = buildMultiplicationCircuit();
    expect(() =>
      evaluateCircuit(circuit, [1n, 2n, 3n, 4n, 5n], FIELD_ORDER)
    ).toThrow(/Witness length/);
  });

  it("should evaluate a custom addition circuit", () => {
    const addCircuit: Circuit = {
      numWires: 4,
      numPublicInputs: 1,
      numPrivateInputs: 2,
      gates: [
        {
          type: "add",
          leftInput: 2,
          rightInput: 3,
          output: 1,
        },
      ],
    };
    // 5 + 7 = 12
    const witness = [1n, 12n, 5n, 7n];
    expect(evaluateCircuit(addCircuit, witness, FIELD_ORDER)).toBe(true);
  });

  it("should reject incorrect addition circuit witness", () => {
    const addCircuit: Circuit = {
      numWires: 4,
      numPublicInputs: 1,
      numPrivateInputs: 2,
      gates: [
        {
          type: "add",
          leftInput: 2,
          rightInput: 3,
          output: 1,
        },
      ],
    };
    // 5 + 7 != 11
    const witness = [1n, 11n, 5n, 7n];
    expect(evaluateCircuit(addCircuit, witness, FIELD_ORDER)).toBe(false);
  });

  it("should evaluate a multi-gate circuit", () => {
    // Circuit: (a + b) * c = d
    // Wire 0 = 1, Wire 1 = d (public output), Wire 2 = a, Wire 3 = b, Wire 4 = c, Wire 5 = a+b (intermediate)
    const circuit: Circuit = {
      numWires: 6,
      numPublicInputs: 1,
      numPrivateInputs: 3,
      gates: [
        { type: "add", leftInput: 2, rightInput: 3, output: 5 }, // a + b = intermediate
        { type: "mul", leftInput: 5, rightInput: 4, output: 1 }, // intermediate * c = d
      ],
    };
    const a = 3n;
    const b = 4n;
    const c = 5n;
    const intermediate = Fr.add(a, b); // 7
    const d = Fr.mul(intermediate, c); // 35
    const witness = [1n, d, a, b, c, intermediate];

    expect(evaluateCircuit(circuit, witness, FIELD_ORDER)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// R1CS conversion and evaluation tests
// ---------------------------------------------------------------------------

describe("R1CS", () => {
  it("should convert multiplication circuit to R1CS", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    expect(r1cs.numConstraints).toBe(1);
    expect(r1cs.numWires).toBe(4);
    expect(r1cs.numPublicInputs).toBe(1);
    expect(r1cs.numPrivateInputs).toBe(2);

    // Check that the constraint selects correct wires
    const constraint = r1cs.constraints[0];
    expect(constraint.a).toEqual([[2, 1n]]); // wire 2 (a)
    expect(constraint.b).toEqual([[3, 1n]]); // wire 3 (b)
    expect(constraint.c).toEqual([[1, 1n]]); // wire 1 (c)
  });

  it("should convert addition gate to R1CS with constant-1 wire", () => {
    const addCircuit: Circuit = {
      numWires: 4,
      numPublicInputs: 1,
      numPrivateInputs: 2,
      gates: [
        { type: "add", leftInput: 2, rightInput: 3, output: 1 },
      ],
    };
    const r1cs = circuitToR1CS(addCircuit);

    expect(r1cs.numConstraints).toBe(1);
    const constraint = r1cs.constraints[0];

    // Addition: (left + right) * 1 = output
    expect(constraint.a).toEqual([
      [2, 1n],
      [3, 1n],
    ]);
    expect(constraint.b).toEqual([[0, 1n]]); // constant 1 wire
    expect(constraint.c).toEqual([[1, 1n]]);
  });

  it("should convert multi-gate circuit to R1CS", () => {
    const circuit: Circuit = {
      numWires: 6,
      numPublicInputs: 1,
      numPrivateInputs: 3,
      gates: [
        { type: "add", leftInput: 2, rightInput: 3, output: 5 },
        { type: "mul", leftInput: 5, rightInput: 4, output: 1 },
      ],
    };
    const r1cs = circuitToR1CS(circuit);

    expect(r1cs.numConstraints).toBe(2);
    // First constraint: addition
    expect(r1cs.constraints[0].b).toEqual([[0, 1n]]);
    // Second constraint: multiplication
    expect(r1cs.constraints[1].a).toEqual([[5, 1n]]);
    expect(r1cs.constraints[1].b).toEqual([[4, 1n]]);
    expect(r1cs.constraints[1].c).toEqual([[1, 1n]]);
  });

  it("should verify R1CS with valid witness", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    const a = 5n;
    const b = 11n;
    const witness = buildWitness(a, b);

    expect(verifyR1CS(r1cs, witness, FIELD_ORDER)).toBe(true);
  });

  it("should verify R1CS with large values", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    const a = FIELD_ORDER - 1n;
    const b = FIELD_ORDER - 1n;
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

  it("should reject R1CS with wrong witness length", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    expect(() => verifyR1CS(r1cs, [1n, 2n], FIELD_ORDER)).toThrow(
      /Witness length/
    );
  });
});

// ---------------------------------------------------------------------------
// evalSparse tests
// ---------------------------------------------------------------------------

describe("evalSparse", () => {
  it("should evaluate empty sparse vector as zero", () => {
    const vec: SparseVector = [];
    const witness = [1n, 21n, 3n, 7n];
    expect(evalSparse(vec, witness, FIELD_ORDER)).toBe(0n);
  });

  it("should evaluate single-element sparse vector", () => {
    const vec: SparseVector = [[2, 1n]];
    const witness = [1n, 21n, 3n, 7n];
    expect(evalSparse(vec, witness, FIELD_ORDER)).toBe(3n);
  });

  it("should evaluate sparse vector with coefficient", () => {
    const vec: SparseVector = [[2, 5n]];
    const witness = [1n, 21n, 3n, 7n];
    expect(evalSparse(vec, witness, FIELD_ORDER)).toBe(15n); // 5 * 3
  });

  it("should evaluate multi-element sparse vector", () => {
    const vec: SparseVector = [
      [2, 1n],
      [3, 1n],
    ];
    const witness = [1n, 21n, 3n, 7n];
    expect(evalSparse(vec, witness, FIELD_ORDER)).toBe(10n); // 3 + 7
  });

  it("should handle modular reduction", () => {
    const vec: SparseVector = [[1, 1n]];
    const witness = [1n, FIELD_ORDER - 1n, 3n, 7n];
    expect(evalSparse(vec, witness, FIELD_ORDER)).toBe(FIELD_ORDER - 1n);
  });

  it("should evaluate correctly with zero coefficient", () => {
    const vec: SparseVector = [[2, 0n]];
    const witness = [1n, 21n, 3n, 7n];
    expect(evalSparse(vec, witness, FIELD_ORDER)).toBe(0n);
  });
});

// ---------------------------------------------------------------------------
// buildWitness tests
// ---------------------------------------------------------------------------

describe("buildWitness", () => {
  it("should build correct witness for small values", () => {
    const witness = buildWitness(4n, 5n);

    expect(witness[0]).toBe(1n); // constant
    expect(witness[1]).toBe(20n); // c = 4 * 5
    expect(witness[2]).toBe(4n); // a
    expect(witness[3]).toBe(5n); // b
    expect(witness).toHaveLength(4);
  });

  it("should build witness with a = 0", () => {
    const witness = buildWitness(0n, 42n);
    expect(witness[1]).toBe(0n); // 0 * 42 = 0
  });

  it("should build witness with field-order-minus-1 (equivalent to -1)", () => {
    const witness = buildWitness(FIELD_ORDER - 1n, 2n);
    // (-1) * 2 = -2 mod p = p - 2
    expect(witness[1]).toBe(FIELD_ORDER - 2n);
  });

  it("should build witness with both inputs = 1", () => {
    const witness = buildWitness(1n, 1n);
    expect(witness[1]).toBe(1n);
  });

  it("should build witness with large values", () => {
    const a = 123456789012345678901234567890n;
    const b = 987654321098765432109876543210n;
    const witness = buildWitness(a, b);
    expect(witness[1]).toBe(Fr.mul(a, b));
    expect(witness[2]).toBe(a);
    expect(witness[3]).toBe(b);
  });
});

// ---------------------------------------------------------------------------
// Trusted setup tests
// ---------------------------------------------------------------------------

describe("Trusted setup", () => {
  it("should produce proving and verification keys", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);
    const { provingKey, verificationKey } = trustedSetup(r1cs);

    // Proving key should have points for each wire
    expect(provingKey.alphaG1).toHaveLength(r1cs.numWires);
    expect(provingKey.betaG2).toHaveLength(r1cs.numWires);

    // Verification key IC should have numPublic + 1 entries (wire 0 + public inputs)
    expect(verificationKey.ic).toHaveLength(1 + r1cs.numPublicInputs);
  });

  it("should produce non-zero key points", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);
    const { verificationKey } = trustedSetup(r1cs);

    // Alpha and beta points should not be the identity
    expect(verificationKey.alphaG1.equals(G1.ProjectivePoint.ZERO)).toBe(false);
  });

  it("should produce different keys on each call (randomized)", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);
    const setup1 = trustedSetup(r1cs);
    const setup2 = trustedSetup(r1cs);

    // Extremely unlikely for two random setups to produce the same alpha
    const aff1 = setup1.verificationKey.alphaG1.toAffine();
    const aff2 = setup2.verificationKey.alphaG1.toAffine();
    expect(aff1.x !== aff2.x || aff1.y !== aff2.y).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Prover and Verifier integration tests
// ---------------------------------------------------------------------------

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

  it("should generate and verify a valid proof for a = 1", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    const witness = buildWitness(1n, 99n);
    const c = witness[1];

    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);
    expect(verify(verificationKey, proof, [c])).toBe(true);
  });

  it("should generate and verify a valid proof for field-edge values", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    // -1 * 2 in the field
    const witness = buildWitness(FIELD_ORDER - 1n, 2n);
    const c = witness[1];

    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);
    expect(verify(verificationKey, proof, [c])).toBe(true);
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

  it("should reject proof verified against a different setup's key", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    const witness = buildWitness(3n, 7n);
    const c = witness[1];

    const setup1 = trustedSetup(r1cs);
    const setup2 = trustedSetup(r1cs);

    const proof = prove(r1cs, setup1.provingKey, witness);
    // Verify with setup2's verification key
    const isValid = verify(setup2.verificationKey, proof, [c]);
    expect(isValid).toBe(false);
  });

  it("should produce different proofs for the same witness (randomized blinding)", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    const witness = buildWitness(3n, 7n);

    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof1 = prove(r1cs, provingKey, witness);
    const proof2 = prove(r1cs, provingKey, witness);

    // Both proofs should verify
    expect(verify(verificationKey, proof1, [witness[1]])).toBe(true);
    expect(verify(verificationKey, proof2, [witness[1]])).toBe(true);

    // But they should be different (different random blinding)
    // Compare piA affine coordinates
    const aff1 = proof1.piA.toAffine();
    const aff2 = proof2.piA.toAffine();
    expect(aff1.x !== aff2.x || aff1.y !== aff2.y).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Proof serialization/deserialization tests
// ---------------------------------------------------------------------------

describe("Proof serialization", () => {
  it("should serialize and deserialize a proof correctly", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    const witness = buildWitness(3n, 7n);
    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);

    const serialized = serializeProof(proof);
    const deserialized = deserializeProof(serialized);

    // Deserialized proof should equal the original
    expect(deserialized.piA.equals(proof.piA)).toBe(true);
    expect(deserialized.piC.equals(proof.piC)).toBe(true);
    // G2 point comparison
    expect(deserialized.piB.equals(proof.piB)).toBe(true);
  });

  it("should produce a valid proof after round-trip serialization", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    const witness = buildWitness(11n, 13n);
    const c = witness[1];
    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);

    const serialized = serializeProof(proof);
    const deserialized = deserializeProof(serialized);

    expect(verify(verificationKey, deserialized, [c])).toBe(true);
  });

  it("should produce valid JSON-serializable structure", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    const witness = buildWitness(2n, 3n);
    const { provingKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);
    const serialized = serializeProof(proof);

    // G1 points should have x, y string fields
    expect(typeof serialized.piA.x).toBe("string");
    expect(typeof serialized.piA.y).toBe("string");
    expect(typeof serialized.piC.x).toBe("string");
    expect(typeof serialized.piC.y).toBe("string");

    // G2 point should have Fp2 coordinate structure
    expect(typeof serialized.piB.x.c0).toBe("string");
    expect(typeof serialized.piB.x.c1).toBe("string");
    expect(typeof serialized.piB.y.c0).toBe("string");
    expect(typeof serialized.piB.y.c1).toBe("string");

    // Values should be parseable as BigInt
    expect(() => BigInt(serialized.piA.x)).not.toThrow();
    expect(() => BigInt(serialized.piB.x.c0)).not.toThrow();

    // Should survive JSON round-trip
    const json = JSON.stringify(serialized);
    const parsed = JSON.parse(json);
    expect(parsed.piA.x).toBe(serialized.piA.x);
  });
});

// ---------------------------------------------------------------------------
// End-to-end flow tests
// ---------------------------------------------------------------------------

describe("End-to-end flow", () => {
  it("should prove and verify: full pipeline with 2 * 3 = 6", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    const a = 2n;
    const b = 3n;
    const witness = buildWitness(a, b);

    // R1CS should be satisfied
    expect(verifyR1CS(r1cs, witness, FIELD_ORDER)).toBe(true);

    // Circuit should evaluate correctly
    expect(evaluateCircuit(circuit, witness, FIELD_ORDER)).toBe(true);

    // Proof should verify
    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);
    expect(verify(verificationKey, proof, [witness[1]])).toBe(true);
  });

  it("should prove and verify: pipeline with very large numbers", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);

    const a = 2n ** 128n;
    const b = 2n ** 64n;
    const witness = buildWitness(a, b);

    expect(verifyR1CS(r1cs, witness, FIELD_ORDER)).toBe(true);

    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);
    expect(verify(verificationKey, proof, [witness[1]])).toBe(true);
  });

  it("should prove and verify: pipeline with 1 * 1 = 1", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);
    const witness = buildWitness(1n, 1n);

    expect(verifyR1CS(r1cs, witness, FIELD_ORDER)).toBe(true);

    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);
    expect(verify(verificationKey, proof, [witness[1]])).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Prover: public wires in A/B constraints (cover lines 291-292, 296-297)
// ---------------------------------------------------------------------------

describe("Prover: public wires in A/B constraints", () => {
  it("should handle a circuit where a public wire appears in A constraint", () => {
    // Build a custom circuit: wire1 (public) * wire2 (private) = wire3 (private)
    // Wire 0 = constant 1, Wire 1 = public input, Wire 2 = private, Wire 3 = output (private)
    // Constraint A selects wire 1 (public), B selects wire 2
    const customCircuit: Circuit = {
      numWires: 4,
      numPublicInputs: 1,
      numPrivateInputs: 2,
      gates: [
        {
          type: "mul",
          leftInput: 1,  // public wire in A
          rightInput: 2,
          output: 3,
        },
      ],
    };

    const r1cs = circuitToR1CS(customCircuit);
    // wire1 = 5 (public), wire2 = 7 (private), wire3 = 35 (private)
    const witness = [1n, 5n, 7n, 35n];

    expect(verifyR1CS(r1cs, witness, FIELD_ORDER)).toBe(true);

    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);
    // Verify with the public input [5n]
    const isValid = verify(verificationKey, proof, [5n]);
    expect(isValid).toBe(true);
  });

  it("should handle a circuit where a public wire appears in B constraint", () => {
    // Build a custom circuit: wire2 (private) * wire1 (public) = wire3 (private)
    // Constraint A selects wire 2, B selects wire 1 (public)
    const customCircuit: Circuit = {
      numWires: 4,
      numPublicInputs: 1,
      numPrivateInputs: 2,
      gates: [
        {
          type: "mul",
          leftInput: 2,
          rightInput: 1,  // public wire in B
          output: 3,
        },
      ],
    };

    const r1cs = circuitToR1CS(customCircuit);
    // wire1 = 5 (public), wire2 = 7 (private), wire3 = 35 (private)
    const witness = [1n, 5n, 7n, 35n];

    expect(verifyR1CS(r1cs, witness, FIELD_ORDER)).toBe(true);

    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);
    const isValid = verify(verificationKey, proof, [5n]);
    expect(isValid).toBe(true);
  });

  it("should handle a circuit where wire 0 (constant) appears in A constraint via addition", () => {
    // Addition gate: wire0 + wire2 = wire1
    // A = [wire0, wire2], B = [wire0 (constant 1)], C = [wire1]
    // This puts wire 0 in A
    const customCircuit: Circuit = {
      numWires: 3,
      numPublicInputs: 1,
      numPrivateInputs: 1,
      gates: [
        {
          type: "add",
          leftInput: 0,  // wire 0 (constant 1) in A
          rightInput: 2,
          output: 1,
        },
      ],
    };

    const r1cs = circuitToR1CS(customCircuit);
    // wire0 = 1, wire2 = 41, wire1 = 42 (1 + 41 = 42)
    const witness = [1n, 42n, 41n];

    expect(verifyR1CS(r1cs, witness, FIELD_ORDER)).toBe(true);

    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);
    const isValid = verify(verificationKey, proof, [42n]);
    expect(isValid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Verifier: error handling (cover lines 68-70 catch block)
// ---------------------------------------------------------------------------

describe("Verifier error handling", () => {
  it("should return false when verify throws internally (corrupted proof)", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);
    const witness = buildWitness(3n, 7n);
    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);

    // Corrupt the verification key IC to cause an error during pairing
    const corruptedVk = {
      ...verificationKey,
      ic: [], // empty IC array will cause index out of bounds
    };

    // This should trigger the catch block and return false
    const result = verify(corruptedVk, proof, [witness[1]]);
    expect(result).toBe(false);
  });

  it("should return false when IC has fewer points than public inputs", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);
    const witness = buildWitness(5n, 11n);
    const { provingKey, verificationKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);

    // Provide ic with only ic[0] but no ic[1] -- accessing ic[1] will be undefined
    const corruptedVk = {
      ...verificationKey,
      ic: [verificationKey.ic[0]], // only 1 entry, but we need 2
    };

    const result = verify(corruptedVk, proof, [witness[1]]);
    expect(result).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Additional edge cases for evalSparse
// ---------------------------------------------------------------------------

describe("evalSparse edge cases", () => {
  it("should handle negative intermediate results correctly (modular arithmetic)", () => {
    // Large coefficient that causes intermediate overflow
    const vec: SparseVector = [
      [1, FIELD_ORDER - 1n],
      [2, 1n],
    ];
    const witness = [1n, 2n, 1n, 0n];
    // (FIELD_ORDER - 1) * 2 + 1 * 1 = 2*FIELD_ORDER - 2 + 1 = -1 mod FIELD_ORDER = FIELD_ORDER - 1
    const result = evalSparse(vec, witness, FIELD_ORDER);
    const expected = ((((FIELD_ORDER - 1n) * 2n) % FIELD_ORDER + 1n) % FIELD_ORDER + FIELD_ORDER) % FIELD_ORDER;
    expect(result).toBe(expected);
  });

  it("should handle all-zero witness", () => {
    const vec: SparseVector = [[0, 1n], [1, 2n]];
    const witness = [0n, 0n, 0n, 0n];
    expect(evalSparse(vec, witness, FIELD_ORDER)).toBe(0n);
  });

  it("should handle large sparse vector with many terms", () => {
    const vec: SparseVector = [
      [0, 1n],
      [1, 2n],
      [2, 3n],
      [3, 4n],
    ];
    const witness = [1n, 1n, 1n, 1n];
    // 1*1 + 2*1 + 3*1 + 4*1 = 10
    expect(evalSparse(vec, witness, FIELD_ORDER)).toBe(10n);
  });
});

// ---------------------------------------------------------------------------
// Additional R1CS edge cases
// ---------------------------------------------------------------------------

describe("R1CS edge cases", () => {
  it("should verify R1CS for addition circuit", () => {
    const addCircuit: Circuit = {
      numWires: 4,
      numPublicInputs: 1,
      numPrivateInputs: 2,
      gates: [
        { type: "add", leftInput: 2, rightInput: 3, output: 1 },
      ],
    };
    const r1cs = circuitToR1CS(addCircuit);
    // 5 + 7 = 12
    const witness = [1n, 12n, 5n, 7n];
    expect(verifyR1CS(r1cs, witness, FIELD_ORDER)).toBe(true);
  });

  it("should reject R1CS for incorrect addition", () => {
    const addCircuit: Circuit = {
      numWires: 4,
      numPublicInputs: 1,
      numPrivateInputs: 2,
      gates: [
        { type: "add", leftInput: 2, rightInput: 3, output: 1 },
      ],
    };
    const r1cs = circuitToR1CS(addCircuit);
    // 5 + 7 != 13
    const witness = [1n, 13n, 5n, 7n];
    expect(verifyR1CS(r1cs, witness, FIELD_ORDER)).toBe(false);
  });

  it("should handle multi-constraint R1CS verification", () => {
    // (a + b) * c = d
    const circuit: Circuit = {
      numWires: 6,
      numPublicInputs: 1,
      numPrivateInputs: 3,
      gates: [
        { type: "add", leftInput: 2, rightInput: 3, output: 5 },
        { type: "mul", leftInput: 5, rightInput: 4, output: 1 },
      ],
    };
    const r1cs = circuitToR1CS(circuit);
    const a = 3n;
    const b = 4n;
    const c = 5n;
    const intermediate = Fr.add(a, b); // 7
    const d = Fr.mul(intermediate, c); // 35
    const witness = [1n, d, a, b, c, intermediate];
    expect(verifyR1CS(r1cs, witness, FIELD_ORDER)).toBe(true);
  });

  it("should reject multi-constraint R1CS with wrong intermediate", () => {
    const circuit: Circuit = {
      numWires: 6,
      numPublicInputs: 1,
      numPrivateInputs: 3,
      gates: [
        { type: "add", leftInput: 2, rightInput: 3, output: 5 },
        { type: "mul", leftInput: 5, rightInput: 4, output: 1 },
      ],
    };
    const r1cs = circuitToR1CS(circuit);
    // Wrong intermediate value
    const witness = [1n, 35n, 3n, 4n, 5n, 8n]; // intermediate should be 7 not 8
    expect(verifyR1CS(r1cs, witness, FIELD_ORDER)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Additional Prover edge cases
// ---------------------------------------------------------------------------

describe("Prover edge cases", () => {
  it("should build witness with both inputs zero", () => {
    const witness = buildWitness(0n, 0n);
    expect(witness[0]).toBe(1n);
    expect(witness[1]).toBe(0n);
    expect(witness[2]).toBe(0n);
    expect(witness[3]).toBe(0n);
  });

  it("should build witness for FIELD_ORDER - 1 squared", () => {
    const a = FIELD_ORDER - 1n;
    const witness = buildWitness(a, a);
    // (-1) * (-1) = 1 in the field
    expect(witness[1]).toBe(1n);
  });

  it("FIELD_ORDER constant should be the BN254 scalar field order", () => {
    expect(FIELD_ORDER).toBe(
      21888242871839275222246405745257275088548364400416034343698204186575808495617n
    );
  });
});

// ---------------------------------------------------------------------------
// Additional proof serialization edge cases
// ---------------------------------------------------------------------------

describe("Proof serialization edge cases", () => {
  it("should serialize proof to valid JSON and back", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);
    const witness = buildWitness(42n, 1337n);
    const { provingKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);

    const serialized = serializeProof(proof);
    const json = JSON.stringify(serialized);
    const parsed = JSON.parse(json);
    const deserialized = deserializeProof(parsed);

    expect(deserialized.piA.equals(proof.piA)).toBe(true);
    expect(deserialized.piB.equals(proof.piB)).toBe(true);
    expect(deserialized.piC.equals(proof.piC)).toBe(true);
  });

  it("serialized proof piB should have correct Fp2 structure", () => {
    const circuit = buildMultiplicationCircuit();
    const r1cs = circuitToR1CS(circuit);
    const witness = buildWitness(7n, 11n);
    const { provingKey } = trustedSetup(r1cs);
    const proof = prove(r1cs, provingKey, witness);

    const serialized = serializeProof(proof);

    // Verify Fp2 coordinates are non-empty strings
    expect(serialized.piB.x.c0.length).toBeGreaterThan(0);
    expect(serialized.piB.x.c1.length).toBeGreaterThan(0);
    expect(serialized.piB.y.c0.length).toBeGreaterThan(0);
    expect(serialized.piB.y.c1.length).toBeGreaterThan(0);

    // Verify they represent valid BigInts
    expect(BigInt(serialized.piB.x.c0) >= 0n).toBe(true);
    expect(BigInt(serialized.piB.x.c1) >= 0n).toBe(true);
    expect(BigInt(serialized.piB.y.c0) >= 0n).toBe(true);
    expect(BigInt(serialized.piB.y.c1) >= 0n).toBe(true);
  });
});
