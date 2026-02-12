import { describe, expect, test } from "bun:test";
import { checkPipeToShell } from "./pipe-checks";
import { ParsedEntry } from "./types";

describe("pipe-checks missing coverage", () => {
  test("handles malformed URL in cred check", () => {
    const args = ["https://[not-a-valid-ip]"];
    const remaining: ParsedEntry[] = [];
    const result = checkPipeToShell(args, remaining, []);
    expect(result).toBeNull();
  });

  test("handles non-string tokens in pipe check", () => {
    const args = ["curl", "http://trusted.com"];
    const remaining: ParsedEntry[] = ["curl", { op: "|" }, { op: ">" }];
    const result = checkPipeToShell(args, remaining, ["trusted.com"]);
    expect(result).toBeNull();
  });
});
