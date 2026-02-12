import { describe, expect, test } from "bun:test";
import { isBypassEnabled, extractEnvVar } from "../src/utils/bypass";

describe("Bypass utilities", () => {
  test("isBypassEnabled recognizes all valid values", () => {
    expect(isBypassEnabled("1")).toBe(true);
    expect(isBypassEnabled("true")).toBe(true);
    expect(isBypassEnabled("TRUE")).toBe(true);
    expect(isBypassEnabled("True")).toBe(true);
    expect(isBypassEnabled("yes")).toBe(true);
    expect(isBypassEnabled("YES")).toBe(true);
    expect(isBypassEnabled("on")).toBe(true);
    expect(isBypassEnabled("ON")).toBe(true);
    expect(isBypassEnabled("enable")).toBe(true);
    expect(isBypassEnabled("enabled")).toBe(true);
  });

  test("isBypassEnabled rejects invalid values", () => {
    expect(isBypassEnabled("0")).toBe(false);
    expect(isBypassEnabled("false")).toBe(false);
    expect(isBypassEnabled("no")).toBe(false);
    expect(isBypassEnabled("off")).toBe(false);
    expect(isBypassEnabled("")).toBe(false);
    expect(isBypassEnabled(undefined)).toBe(false);
    expect(isBypassEnabled("random")).toBe(false);
    expect(isBypassEnabled("2")).toBe(false);
  });

  test("extractEnvVar finds variable in tokens", () => {
    const tokens = ["SHELLSHIELD_SKIP=1", "rm", "-rf", "/tmp"];
    expect(extractEnvVar(tokens, "SHELLSHIELD_SKIP")).toBe("1");
  });

  test("extractEnvVar handles value with equals sign", () => {
    const tokens = ["FOO=bar=baz", "echo", "test"];
    expect(extractEnvVar(tokens, "FOO")).toBe("bar=baz");
  });

  test("extractEnvVar returns undefined when not found", () => {
    const tokens = ["OTHER=value", "rm", "-rf", "/tmp"];
    expect(extractEnvVar(tokens, "SHELLSHIELD_SKIP")).toBeUndefined();
  });

  test("extractEnvVar stops at non-string token", () => {
    const tokens = ["FOO=bar", { op: "|" }, "SHELLSHIELD_SKIP=1"];
    expect(extractEnvVar(tokens, "SHELLSHIELD_SKIP")).toBeUndefined();
  });
});