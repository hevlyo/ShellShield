export const DEFAULT_BLOCKED = new Set([
  // File deletion commands
  "rm", "shred", "unlink", "wipe", "srm",
  // Disk/partition manipulation commands
  "mkfs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs", "mkfs.ntfs", "mkfs.fat", "mkfs.vfat",
  "fdisk", "parted", "gdisk", "cfdisk", "sfdisk",
  "dd", "blkid", "wipefs", "badblocks",
  // System modification commands
  "systemctl", "init", "shutdown", "reboot", "poweroff", "halt",
  "iptables", "ip6tables", "nft", "ufw",
  // Privilege escalation
  "su", "sudo", "doas", "pkexec",
  // User/group management
  "userdel", "groupdel", "passwd", "chpasswd",
]);
export const SHELL_COMMANDS = new Set([
  "sh",
  "bash",
  "zsh",
  "dash",
  "fish",
  "pwsh",
  "powershell",
]);
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
