import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { printUsage, runDemo, runProve, main } from "./cli.js";

describe("CLI: printUsage", () => {
  it("should print usage information", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    printUsage();
    const output = spy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("Zero-Knowledge Proof CLI");
    expect(output).toContain("Usage:");
    expect(output).toContain("demo");
    expect(output).toContain("prove");
    expect(output).toContain("verify");
    spy.mockRestore();
  });
});

describe("CLI: runDemo", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
  });

  it("should run a full demo for 3 * 7", () => {
    runDemo("3", "7");
    const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("a = 3, b = 7");
    expect(output).toContain("Building arithmetic circuit");
    expect(output).toContain("Converting to R1CS");
    expect(output).toContain("Building witness");
    expect(output).toContain("R1CS satisfied: true");
    expect(output).toContain("Performing trusted setup");
    expect(output).toContain("Generating proof");
    expect(output).toContain("Verifying proof");
    expect(output).toContain("VALID");
    expect(output).toContain("Soundness Check");
    expect(output).toContain("INVALID (expected)");
  });

  it("should display field order", () => {
    runDemo("2", "5");
    const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("Field order:");
  });

  it("should display circuit gate info", () => {
    runDemo("4", "6");
    const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("1 gate(s)");
    expect(output).toContain("4 wire(s)");
  });

  it("should display witness values", () => {
    runDemo("3", "7");
    const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("Witness: [1, 21, 3, 7]");
  });

  it("should display proof timing information", () => {
    runDemo("2", "3");
    const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toMatch(/Setup completed in \d+\.?\d*ms/);
    expect(output).toMatch(/Proof generated in \d+\.?\d*ms/);
    expect(output).toMatch(/Verified in \d+\.?\d*ms/);
  });

  it("should display serialized proof elements", () => {
    runDemo("5", "11");
    const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("piA:");
    expect(output).toContain("piB:");
    expect(output).toContain("piC:");
  });

  it("should confirm prover knowledge statement", () => {
    runDemo("2", "3");
    const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain(
      "The verifier is convinced that the prover knows a and b"
    );
    expect(output).toContain("without learning a or b");
  });

  it("should display the correct public output c", () => {
    runDemo("6", "7");
    const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("Public output:  c = 42");
  });

  it("should show that (a and b are NOT revealed)", () => {
    runDemo("3", "7");
    const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("a and b are NOT revealed to the verifier");
  });

  it("should run demo with large numbers", () => {
    runDemo("42", "1337");
    const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("a = 42, b = 1337");
    expect(output).toContain("VALID");
  });
});

describe("CLI: runProve", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it("should output valid JSON with proof and publicInput", () => {
    runProve("3", "7");
    const jsonOutput = logSpy.mock.calls[0][0];
    const parsed = JSON.parse(jsonOutput);
    expect(parsed).toHaveProperty("publicInput");
    expect(parsed).toHaveProperty("proof");
    expect(parsed.publicInput).toBe("21");
  });

  it("should output proof with G1 and G2 point structures", () => {
    runProve("11", "13");
    const jsonOutput = logSpy.mock.calls[0][0];
    const parsed = JSON.parse(jsonOutput);
    // G1 points
    expect(typeof parsed.proof.piA.x).toBe("string");
    expect(typeof parsed.proof.piA.y).toBe("string");
    expect(typeof parsed.proof.piC.x).toBe("string");
    expect(typeof parsed.proof.piC.y).toBe("string");
    // G2 point
    expect(typeof parsed.proof.piB.x.c0).toBe("string");
    expect(typeof parsed.proof.piB.x.c1).toBe("string");
    expect(typeof parsed.proof.piB.y.c0).toBe("string");
    expect(typeof parsed.proof.piB.y.c1).toBe("string");
  });

  it("should output correct publicInput for large values", () => {
    runProve("100", "200");
    const jsonOutput = logSpy.mock.calls[0][0];
    const parsed = JSON.parse(jsonOutput);
    expect(parsed.publicInput).toBe("20000");
  });

  it("should produce JSON that can be parsed back", () => {
    runProve("7", "11");
    const jsonOutput = logSpy.mock.calls[0][0];
    expect(() => JSON.parse(jsonOutput)).not.toThrow();
    const parsed = JSON.parse(jsonOutput);
    // Validate BigInt-parseable strings
    expect(() => BigInt(parsed.publicInput)).not.toThrow();
    expect(() => BigInt(parsed.proof.piA.x)).not.toThrow();
  });
});

describe("CLI: main (argument parsing)", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {}) as never);
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
    exitSpy.mockRestore();
  });

  it("should print usage with no arguments", () => {
    main([]);
    const output = logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("Zero-Knowledge Proof CLI");
  });

  it("should print usage for --help", () => {
    main(["--help"]);
    const output = logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("Zero-Knowledge Proof CLI");
  });

  it("should print usage for -h", () => {
    main(["-h"]);
    const output = logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("Zero-Knowledge Proof CLI");
  });

  it("should print usage for help command", () => {
    main(["help"]);
    const output = logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("Zero-Knowledge Proof CLI");
  });

  it("should call process.exit(1) when demo has insufficient args", () => {
    exitSpy.mockImplementation((() => { throw new Error("process.exit"); }) as never);
    expect(() => main(["demo", "3"])).toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith("Usage: demo <a> <b>");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("should call process.exit(1) when prove has insufficient args", () => {
    exitSpy.mockImplementation((() => { throw new Error("process.exit"); }) as never);
    expect(() => main(["prove"])).toThrow("process.exit");
    expect(errorSpy).toHaveBeenCalledWith("Usage: prove <a> <b>");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("should run demo when two args are provided without a command", () => {
    main(["5", "11"]);
    const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("a = 5, b = 11");
    expect(output).toContain("VALID");
  });

  it("should run demo command", () => {
    main(["demo", "2", "3"]);
    const output = logSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("a = 2, b = 3");
    expect(output).toContain("VALID");
  });

  it("should run prove command", () => {
    main(["prove", "3", "7"]);
    const jsonOutput = logSpy.mock.calls[0][0];
    const parsed = JSON.parse(jsonOutput);
    expect(parsed.publicInput).toBe("21");
  });

  it("should print usage for unknown single argument", () => {
    main(["unknown"]);
    const output = logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(output).toContain("Zero-Knowledge Proof CLI");
  });

  it("should call process.exit(1) for demo with only command name", () => {
    exitSpy.mockImplementation((() => { throw new Error("process.exit"); }) as never);
    expect(() => main(["demo"])).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("should call process.exit(1) for prove with only one number", () => {
    exitSpy.mockImplementation((() => { throw new Error("process.exit"); }) as never);
    expect(() => main(["prove", "5"])).toThrow("process.exit");
    expect(exitSpy).toHaveBeenCalledWith(1);
  });
});
