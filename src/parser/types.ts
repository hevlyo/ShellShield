export type ParsedEntry = string | { op: string };

export function isOperator(entry: ParsedEntry): entry is { op: string } {
  return typeof entry === "object" && entry !== null && "op" in entry;
}
