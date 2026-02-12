export const SHELL_INTERPRETERS = [
  "sh", "bash", "zsh", "dash", "fish", "pwsh", "powershell"
];

export const CODE_EXECUTORS = [
  ...SHELL_INTERPRETERS,
  "python", "python3", "python2",
  "perl", "ruby", "node", "bun", "php",
];

export const DOWNLOAD_COMMANDS = ["curl", "wget"];

export const CODE_EXECUTION_FLAGS = ["-c", "-e", "-command", "--command"];

const MAX_INPUT_LENGTH = 10000;

export function safeRegexTest(pattern: RegExp, input: string): boolean {
  if (input.length > MAX_INPUT_LENGTH) {
    return false;
  }
  return pattern.test(input);
}

export function createPipeToPattern(
  sourceCommands: string[],
  targetCommands: string[]
): RegExp {
  const source = sourceCommands.join("|");
  const target = targetCommands.join("|");
  return new RegExp(`\\b(?:${source})\\b[^|]*?\\|\\s*(?:${target})\\b`, "i");
}

const NON_SHELL_EXECUTORS = [
  "python", "python3", "python2",
  "perl", "ruby", "node", "bun", "php",
];

export const PIPE_PATTERNS = {
  base64ToShell: /base64\s{0,10}-d\s{0,10}\|\s{0,10}(?:sh|bash|zsh)\b/i,
  xxdToShell: /xxd\s{0,10}-r\s{0,10}-p\s{0,10}\|\s{0,10}(?:sh|bash|zsh)\b/i,
  downloadToInterpreter: new RegExp(
    `\\b(?:${DOWNLOAD_COMMANDS.join("|")})\\b[^|]{0,1000}?\\|\\s{0,10}(?:${NON_SHELL_EXECUTORS.join("|")})\\b`,
    "i"
  ),
  sedToShell: /\bsed\b[^|]{0,500}?\|\s{0,10}(?:sh|bash|zsh)\b/i,
  awkToShell: /\bawk\b[^|]{0,500}?\|\s{0,10}(?:sh|bash|zsh)\b/i,
  opensslToShell: /\bopenssl\b[^|]{0,500}?\|\s{0,10}(?:sh|bash|zsh)\b/i,
  tarToShell: /\bg?tar\b[^|]{0,500}?\|\s{0,10}(?:sh|bash|zsh)\b/i,
};

export const PROCESS_SUBSTITUTION_PATTERNS = {
  standard: /<\(\s{0,10}(?:curl|wget)\b/i,
  withBash: /bash[^|]{0,100}?<\((?:curl|wget)\)/i,
};

export const EVAL_PATTERNS = {
  withCurl: /eval\s{0,10}\$\(curl\b/i,
  withWget: /eval\s{0,10}\$\(wget\b/i,
  withBacktickCurl: /eval\s{0,10}`curl\b/i,
  withBacktickWget: /eval\s{0,10}`wget\b/i,
};

export const POWERSHELL_PATTERNS = {
  encodedCommand: /\b(?:pwsh|powershell)\b\s{0,10}(?:-encodedcommand|-enc)\b/i,
};

export function validatePatternPerformance(
  pattern: RegExp,
  testInput: string,
  maxDurationMs: number = 100
): boolean {
  const start = performance.now();
  pattern.test(testInput);
  const duration = performance.now() - start;
  return duration < maxDurationMs;
}