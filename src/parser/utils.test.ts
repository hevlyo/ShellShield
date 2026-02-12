import { describe, expect, test } from "bun:test";
import { normalizeCommandName, resolveVariable, filterFlags, getTrashSuggestion } from "./utils";

describe("Parser Utils", () => {
  test("normalizeCommandName handles empty input", () => {
    expect(normalizeCommandName("")).toBe("");
  });

  test("resolveVariable handles invalid format", () => {
    expect(resolveVariable("NOT_A_VAR", {})).toBe("NOT_A_VAR");
    expect(resolveVariable("$", {})).toBe("$");
    expect(resolveVariable("${}", {})).toBe("${}");
  });

  test("resolveVariable handles empty result", () => {
    expect(resolveVariable("$EMPTY", { EMPTY: "" })).toBe("");
  });

  test("resolveVariable handles partial expansion", () => {
    expect(resolveVariable("/bin/$VAR", { VAR: "rm" })).toBe("/bin/rm");
    expect(resolveVariable("${VAR:-default}/path", { VAR: "" })).toBe("default/path");
    expect(resolveVariable("prefix_${VAR}", { VAR: "suffix" })).toBe("prefix_suffix");
  });

  test("filterFlags identifies flags correctly", () => {
    expect(filterFlags(["-f", "--force", "file.txt"])).toEqual(["file.txt"]);
  });

  test("getTrashSuggestion handles empty file list", () => {
    expect(getTrashSuggestion([])).toBe("trash <files>");
  });
});
