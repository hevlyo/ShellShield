import { describe, expect, test } from "bun:test";
import { parseTypeOutput } from "../src/shell-context";

describe("shell context type output parsing", () => {
  test("parses bash aliased-to output", () => {
    const entry = parseTypeOutput("ls is aliased to 'ls --color=auto'");
    expect(entry.kind).toBe("alias");
    expect(entry.expansion).toBe("ls --color=auto");
  });

  test("parses zsh alias-for output (unquoted)", () => {
    const entry = parseTypeOutput("ls is an alias for ls -G");
    expect(entry.kind).toBe("alias");
    expect(entry.expansion).toBe("ls -G");
  });

  test("parses zsh alias-for output (quoted)", () => {
    const entry = parseTypeOutput("rm is an alias for 'rm -i'");
    expect(entry.kind).toBe("alias");
    expect(entry.expansion).toBe("rm -i");
  });

  test("parses function output", () => {
    const entry = parseTypeOutput("foo is a function\nfoo () { echo hi; }");
    expect(entry.kind).toBe("function");
  });

  test("parses file output", () => {
    const entry = parseTypeOutput("rm is /usr/bin/rm");
    expect(entry.kind).toBe("file");
  });

  test("parses hashed output", () => {
    const entry = parseTypeOutput("rm is hashed (/usr/bin/rm)");
    expect(entry.kind).toBe("file");
  });
});
