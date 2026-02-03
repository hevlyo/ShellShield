export interface ToolInput {
  tool_input?: {
    command?: string;
  };
}

export interface Config {
  blocked: Set<string>;
  allowed: Set<string>;
  trustedDomains: string[];
  threshold: number;
}

export interface TerminalInjectionResult {
  detected: boolean;
  reason?: string;
}

export type BlockResult =
  | { blocked: false }
  | { blocked: true; reason: string; suggestion: string };
