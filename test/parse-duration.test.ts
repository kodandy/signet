import { describe, test, expect } from "vitest";
import { parseDuration } from "../src/index";

describe("parseDuration", () => {
  test("parses minutes", () => {
    expect(parseDuration("30m")).toBe(30 * 60 * 1000);
    expect(parseDuration("1m")).toBe(60 * 1000);
    expect(parseDuration("0m")).toBe(0);
  });

  test("parses hours", () => {
    expect(parseDuration("4h")).toBe(4 * 60 * 60 * 1000);
    expect(parseDuration("1h")).toBe(3600000);
    expect(parseDuration("24h")).toBe(86400000);
  });

  test("parses days", () => {
    expect(parseDuration("1d")).toBe(24 * 60 * 60 * 1000);
    expect(parseDuration("7d")).toBe(7 * 24 * 60 * 60 * 1000);
    expect(parseDuration("30d")).toBe(30 * 24 * 60 * 60 * 1000);
  });

  test("returns null for invalid input", () => {
    expect(parseDuration("")).toBeNull();
    expect(parseDuration("abc")).toBeNull();
    expect(parseDuration("4")).toBeNull();
    expect(parseDuration("h")).toBeNull();
    expect(parseDuration("4x")).toBeNull();
  });

  test("returns null for unsupported units", () => {
    expect(parseDuration("4s")).toBeNull();
    expect(parseDuration("4w")).toBeNull();
    expect(parseDuration("4y")).toBeNull();
  });

  test("returns null for negative or decimal values", () => {
    expect(parseDuration("-1h")).toBeNull();
    expect(parseDuration("1.5h")).toBeNull();
  });

  test("returns null for whitespace or extra characters", () => {
    expect(parseDuration(" 4h")).toBeNull();
    expect(parseDuration("4h ")).toBeNull();
    expect(parseDuration("4hh")).toBeNull();
  });
});
