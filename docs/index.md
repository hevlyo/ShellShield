---
title: ShellShield
---

# ShellShield

Install:

```bash
curl -fsSL https://hevlyo.github.io/ShellShield/install.sh -o /tmp/shellshield-install.sh
SHELLSHIELD_INSTALL_SHA256="363aeea624bf28102c7fc096239293d749f35ff9e868df1c1b12da571ef4a254" \
  bash /tmp/shellshield-install.sh
```

SHA256 (install.sh): `363aeea624bf28102c7fc096239293d749f35ff9e868df1c1b12da571ef4a254`

GPG verification (optional):

```bash
curl -fsSL https://hevlyo.github.io/ShellShield/install.sh.asc -o /tmp/shellshield-install.sh.asc
gpg --keyserver keys.openpgp.org --recv-keys 744857708F52A3F4885EDA5CF38DA114834A9FA0
gpg --verify /tmp/shellshield-install.sh.asc /tmp/shellshield-install.sh
```

Installer script:

`/install.sh`
