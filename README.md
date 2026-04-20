# LilZey LDAP Shell

LilZey is a Python-based interactive shell designed for Active Directory interactions via LDAP. It provides comprehensive commands for enumerating domains, managing users and computers, checking ACLs, setting object properties, and more.

## Installation

1. Clone or download the repository.
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

*(This project mainly relies on `ldap3`, `impacket`, and `rich`.)*

## Usage

Start the interactive shell:

```bash
python3 ldapshell.py
```

### Connection Examples

Once inside the shell, you can connect using various authentication methods:

**Password Authentication:**
```bash
shell> connect administrator Password! domain.local 10.10.10.10
```

**Kerberos Authentication:**
```bash
shell> connectk administrator Password! domain.local 10.10.10.10
```

**Pass-the-Hash (NT Hash):**
```bash
shell> connect_hash administrator e52cac67419a9a224a3b108f3fa6cb6d domain.local 10.10.10.10
```

**SSL (LDAPS):**
```bash
shell> connectssl administrator Password! domain.local 10.10.10.10
```

*(You can also pass connection parameters directly as command-line arguments to `ldapshell.py` to auto-connect on startup.)*

## Overview of Supported Commands

Once connected, type `help` to see the full menu. Here are some of the most common actions:

- **Sessions Management**: 
  - `sessions` / `use <id>` / `status` / `disconnect`
- **Enumeration**: 
  - `users` / `groups` / `computers` / `categories` / `kerberoasting`
- **Querying & Cache**: 
  - `query <username>` / `batch_lookup` / `offline_search <username>`
- **Object ACL & Attributes**: 
  - `checkacl` / `genericall <target>` / `setowner <target>` / `adduac <username> <FLAG>` / `rmuac <username> <FLAG>`
- **Active Directory Exploitation**: 
  - `addmember <group> <user>` / `addcomputer <name> <password>` / `setpass <user> <newpassword>` / `getgmsa <account>`
- **SMB Shares**: 
  - `shares <ip>` to enumerate.
  - `shares <ip> <share> get <file>` to download.

## Full walkthrough
https://youtu.be/KHmygGIDWRQ

## Credits
https://github.com/fortra/impacket
https://github.com/CravateRouge/bloodyAD
https://github.com/L1nvx/AceWalk

