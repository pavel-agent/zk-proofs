/**
 * Arithmetic Circuit Representation
 *
 * Represents computations as a directed acyclic graph of addition and
 * multiplication gates operating over a prime field. Each gate takes two
 * inputs and produces one output. Wires carry field-element values.
 */

export type GateType = "add" | "mul";

export interface Gate {
  type: GateType;
  /** Index of the left input wire */
  leftInput: number;
  /** Index of the right input wire */
  rightInput: number;
  /** Index of the output wire */
  output: number;
}

export interface Circuit {
  /** Total number of wires (including the constant-1 wire at index 0) */
  numWires: number;
  /** Number of public input wires (positioned right after wire 0) */
  numPublicInputs: number;
  /** Number of private (witness) input wires */
  numPrivateInputs: number;
  /** Ordered list of gates */
  gates: Gate[];
}

/**
 * Build the multiplication circuit for: a * b = c
 *
 * Wire layout:
 *   0 -> constant "1"
 *   1 -> public output c
 *   2 -> private input a
 *   3 -> private input b
 *
 * Single multiplication gate: wire2 * wire3 = wire1
 */
export function buildMultiplicationCircuit(): Circuit {
  return {
    numWires: 4,
    numPublicInputs: 1, // c
    numPrivateInputs: 2, // a, b
    gates: [
      {
        type: "mul",
        leftInput: 2,
        rightInput: 3,
        output: 1,
      },
    ],
  };
}

/**
 * Evaluate the circuit given a full witness assignment (all wire values).
 * Returns true if every gate constraint is satisfied.
 */
export function evaluateCircuit(
  circuit: Circuit,
  witness: bigint[],
  fieldOrder: bigint
): boolean {
  if (witness.length !== circuit.numWires) {
    throw new Error(
      `Witness length ${witness.length} does not match circuit wire count ${circuit.numWires}`
    );
  }

  for (const gate of circuit.gates) {
    const left = witness[gate.leftInput];
    const right = witness[gate.rightInput];
    const out = witness[gate.output];

    let expected: bigint;
    if (gate.type === "add") {
      expected = (left + right) % fieldOrder;
    } else {
      expected = (left * right) % fieldOrder;
    }

    if (expected !== out) {
      return false;
    }
  }

  return true;
}
