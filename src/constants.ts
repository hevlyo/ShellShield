export const DEFAULT_BLOCKED = new Set(["rm", "shred", "unlink", "wipe", "srm"]);
export const SHELL_COMMANDS = new Set(["sh", "bash", "zsh", "dash"]);
export const CRITICAL_PATHS = new Set([
  "/",
  "/etc",
  "/usr",
  "/var",
  "/bin",
  "/sbin",
  "/lib",
  "/boot",
  "/root",
  "/dev",
  "/proc",
  "/sys",
  "c:/windows",
  "c:/windows/system32",
  "c:/program files",
  "c:/program files (x86)",
  "c:/users",
  "c:windows",
  "c:windowssystem32",
  "c:program files",
  "c:users",
]);

export const DEFAULT_TRUSTED_DOMAINS = [
  "github.com",
  "raw.githubusercontent.com",
  "get.docker.com",
  "sh.rustup.rs",
  "bun.sh",
  "install.python-poetry.org",
  "raw.github.com",
];

export const SENSITIVE_PATTERNS = [
  /\/\.ssh\//,
  /\/\.bashrc$/,
  /\/\.zshrc$/,
  /\/\.profile$/,
  /\/\.gitconfig$/,
];
