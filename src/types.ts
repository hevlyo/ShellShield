export interface ToolInput {
  command?: string;
  tool_input?: {
    command?: string;
  };
}

export interface Config {
  blocked: Set<string>;
  allowed: Set<string>;
  trustedDomains: string[];
  threshold: number;
  mode: "enforce" | "permissive" | "interactive";
  customRules: Array<{ pattern: string; suggestion: string }>;
  maxSubshellDepth: number;
  contextPath?: string;
}

export interface TerminalInjectionResult {
  detected: boolean;
  reason?: string;
}

export type BlockResult =
  | { blocked: false; reason?: string; suggestion?: string; rule?: string }
  | { blocked: true; reason: string; suggestion: string; rule?: string };
