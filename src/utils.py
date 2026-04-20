import time
import ssl
import os
from ldap3 import Server, ALL, Connection, NTLM, SUBTREE, Tls, MODIFY_ADD, MODIFY_REPLACE, SASL, KERBEROS
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID, ACE, ACCESS_ALLOWED_ACE, ACCESS_MASK
from rich import print
import readline
import rlcompleter
import atexit
import heapq
import shlex

from src.structs import Session, Queue, DecisionNode, TreeNode, HistoryNode, SinglyLinkedList, SessionManager, BSTNode, UserCacheBST
UAC_FLAGS = {
    "SCRIPT": 0x00000001,
    "ACCOUNTDISABLE": 0x00000002,
    "HOMEDIR_REQUIRED": 0x00000008,
    "LOCKOUT": 0x00000010,
    "PASSWD_NOTREQD": 0x00000020,
    "PASSWD_CANT_CHANGE": 0x00000040,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x00000080,
    "TEMP_DUPLICATE_ACCOUNT": 0x00000100,
    "NORMAL_ACCOUNT": 0x00000200,
    "INTERDOMAIN_TRUST_ACCOUNT": 0x00000800,
    "WORKSTATION_TRUST_ACCOUNT": 0x00001000,
    "SERVER_TRUST_ACCOUNT": 0x00002000,
    "DONT_EXPIRE_PASSWORD": 0x00010000,
    "MNS_LOGON_ACCOUNT": 0x00020000,
    "SMARTCARD_REQUIRED": 0x00040000,
    "TRUSTED_FOR_DELEGATION": 0x00080000,
    "NOT_DELEGATED": 0x00100000,
    "USE_DES_KEY_ONLY": 0x00200000,
    "DONT_REQ_PREAUTH": 0x00400000,
    "PASSWORD_EXPIRED": 0x00800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x01000000,
    "PARTIAL_SECRETS_ACCOUNT": 0x04000000
}

COMMANDS = [
    "connect", "connectk", "connectssl", "connect_hash", "disconnect", "use",
    "sessions", "status", "query", "history", "batch_lookup",
    "categories", "groups", "users", "computers", "kerberoasting", "checkacl", "addmember",
    "setpass", "help", "exit", "savepassword", "show_all_history", "offline_search", "shares",
    "get_sid", "getgmsa", "setowner", "genericall", "adduac", "rmuac", "addcomputer",
    "ldap", "maq"
]

def shell_completer(text, state):
    options = [cmd for cmd in COMMANDS if cmd.startswith(text)]
    if state < len(options):
        return options[state]
    return None

readline.set_completer(shell_completer)
readline.parse_and_bind("tab: complete")


def show_menu():
    print("""
    Available Commands :
    connect <username> <password> <domain> <dc_ip> - Connect to AD
    connectk <username> <password> <domain> <dc_ip> - Connect to AD via Kerberos
    connectssl <username> <password> <domain> <dc_ip> - Connect to AD via SSL
    connect_hash <username> <nthash> <domain> <dc_ip> - Connect using NT Hash
    disconnect   - Disconnect from AD
    use <id>     - Use a specific session
    sessions     - Current sessions
    status       - Show status
    query        - Query for user - query <username>
    history      - Check history pop
    batch_lookup - batch users
    categories   - Show categories
    groups       - List all groups
    users        - List all users
    computers    - List all computers
    kerberoasting- List kerberoastable accounts
    checkacl     - Check ACLs for current session user using aclftw
    addmember    - Add member to group - addmember <group> <user>
    setpass      - Set user password - setpass <user> <newpassword>
    offline_search - Search cached users offline - offline_search <username>
    shares       - Enumerate SMB shares  - shares <target_ip>
                   List files in share   - shares <target_ip> <share>
                   Browse subdirectory   - shares <target_ip> "<share>\\<subdir>"
                   Download from share   - shares <target_ip> <share> get <file>
                   Upload to share       - shares <target_ip> <share> put <file>
                   Tip: use quotes for multi-word shares e.g. "Department Shares"
    get_sid      - Get user's SID       - get_sid <username>
    getgmsa      - Get GMSA password    - getgmsa <account>
    setowner     - Set object owner     - setowner <target_dn>
    genericall   - Grant GenericAll     - genericall <target_dn>
    adduac       - Add UAC flag         - adduac <username> <FLAG>
    rmuac        - Remove UAC flag      - rmuac <username> <FLAG>
    addcomputer  - Add a computer       - addcomputer <computername> <password>
    ldap         - Get domain info      - ldap <ip>
    maq          - Get MAQ              - maq
    savepassword - Save a password      - savepassword <password>
    show_all_history - Show all query history
    help         - Menu
    exit         - Exit
    """)
def infer_netbios(domain):
    return domain.split('.')[0].upper()
def domain_to_dn(domain):
    return ','.join(f'DC={x}' for x in domain.split('.'))

def check_connection(tree, connected):
    print(f"Decision: {tree.question}")
    if connected:
        print(f" -> [bold green]Yes[/bold green]: {tree.right.question}")
    else:
        print(f" -> [bold red]No[/bold red]: {tree.left.question}")

WELL_KNOWN_SIDS = {
    "S-1-0-0": "Nobody",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-17": "IIS APPPOOL",
    "S-1-5-18": "Local System",
    "S-1-5-19": "NT Authority\\Local Service",
    "S-1-5-20": "NT Authority\\Network Service",
}

def resolve_sid(conn, base_dn, sid):
    """Resolve a SID string to its friendly name."""
    if sid in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid]
    # try LDAP lookup for domain-specific SIDs
    try:
        conn.search(base_dn, f"(objectSid={sid})", attributes=["cn"])
        if conn.entries:
            return str(conn.entries[0].cn)
    except Exception:
        pass
    return sid

def resolve_member_name(conn, base_dn, member):
    """Resolve a member value to a friendly name. Handles both DN and SID formats."""
    if member.startswith("CN="):
        cn = member.split(",")[0].replace("CN=", "")
        # Foreign Security Principals have SIDs as their CN
        if cn.startswith("S-1-"):
            return resolve_sid(conn, base_dn, cn)
        return cn
    if member.startswith("S-1-"):
        return resolve_sid(conn, base_dn, member)
    return member

def sid_to_string(binary_sid):
    """Convert a binary SID (bytes) to its string representation S-1-5-21-..."""
    if isinstance(binary_sid, str):
        return binary_sid
    revision = binary_sid[0]
    sub_authority_count = binary_sid[1]
    authority = int.from_bytes(binary_sid[2:8], byteorder='big')
    subs = []
    for i in range(sub_authority_count):
        offset = 8 + i * 4
        subs.append(int.from_bytes(binary_sid[offset:offset+4], byteorder='little'))
    return f"S-{revision}-{authority}-" + "-".join(str(s) for s in subs)

def save_password(password):
    filename = "passwords.txt"

    existing = set()

    if os.path.exists(filename):
        with open(filename, "r") as f:
            existing = {line.strip() for line in f}
    if password in existing:
        print("[bold yellow][!] Password already in list[/bold yellow]")
        return

    with open(filename, "a") as f:
        f.write(password + "\n")

    print(f"[bold green][+] Password saved: {password}[/bold green]")

