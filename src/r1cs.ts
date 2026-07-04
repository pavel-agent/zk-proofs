/**
 * Rank-1 Constraint System (R1CS)
 *
 * An R1CS encodes an arithmetic circuit as a system of constraints of the form:
 *
 *   (A_i . w) * (B_i . w) = (C_i . w)
 *
 * where w is the witness vector (wire values), and A_i, B_i, C_i are sparse
 * row vectors (one per constraint). The dot product selects and scales wire
 * values, and the constraint asserts the product relationship.
 *
 * For our a * b = c circuit we have one constraint:
 *   A = [0, 0, 1, 0]   (selects wire 2 = a)
 *   B = [0, 0, 0, 1]   (selects wire 3 = b)
 *   C = [0, 1, 0, 0]   (selects wire 1 = c)
 */

import type { Circuit } from "./circuit.js";

/** Sparse representation: array of [wireIndex, coefficient] pairs */
export type SparseVector = [number, bigint][];

export interface R1CSConstraint {
  a: SparseVector;
  b: SparseVector;
  c: SparseVector;
}

export interface R1CS {
  numWires: number;
  numConstraints: number;
  numPublicInputs: number;
  numPrivateInputs: number;
  constraints: R1CSConstraint[];
}

/**
 * Convert an arithmetic circuit into an R1CS.
 *
 * For a multiplication gate (L * R = O):
 *   A selects the left input, B selects the right input, C selects the output.
 *
 * For an addition gate (L + R = O), we encode it as:
 *   A = (L + R), B = (1), C = (O)
 *   i.e., (L + R) * 1 = O
 */
export function circuitToR1CS(circuit: Circuit): R1CS {
  const constraints: R1CSConstraint[] = [];

  for (const gate of circuit.gates) {
    if (gate.type === "mul") {
      constraints.push({
        a: [[gate.leftInput, 1n]],
        b: [[gate.rightInput, 1n]],
        c: [[gate.output, 1n]],
      });
    } else {
      // Addition: (left + right) * 1 = output
      constraints.push({
        a: [
          [gate.leftInput, 1n],
          [gate.rightInput, 1n],
        ],
        b: [[0, 1n]], // wire 0 is constant 1
        c: [[gate.output, 1n]],
      });
    }
  }

  return {
    numWires: circuit.numWires,
    numConstraints: constraints.length,
    numPublicInputs: circuit.numPublicInputs,
    numPrivateInputs: circuit.numPrivateInputs,
    constraints,
  };
}

/**
 * Evaluate a sparse vector dot product with the witness.
 */
export function evalSparse(
  vec: SparseVector,
  witness: bigint[],
  fieldOrder: bigint
): bigint {
  let result = 0n;
  for (const [idx, coeff] of vec) {
    result = (result + coeff * witness[idx]) % fieldOrder;
  }
  // Ensure positive
  return ((result % fieldOrder) + fieldOrder) % fieldOrder;
}

/**
 * Check that the witness satisfies all R1CS constraints.
 */
export function verifyR1CS(
  r1cs: R1CS,
  witness: bigint[],
  fieldOrder: bigint
): boolean {
  if (witness.length !== r1cs.numWires) {
    throw new Error(
      `Witness length ${witness.length} does not match R1CS wire count ${r1cs.numWires}`
    );
  }

  for (let i = 0; i < r1cs.constraints.length; i++) {
    const { a, b, c } = r1cs.constraints[i];

    const aVal = evalSparse(a, witness, fieldOrder);
    const bVal = evalSparse(b, witness, fieldOrder);
    const cVal = evalSparse(c, witness, fieldOrder);

    const product = (aVal * bVal) % fieldOrder;
    if (product !== cVal) {
      return false;
    }
  }

  return true;
}
