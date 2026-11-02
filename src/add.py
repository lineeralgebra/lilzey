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

from src.auth import samr_set_password
from src.utils import UAC_FLAGS
def add_member(conn, base_dn, group_name, user_name):
    conn.search(base_dn, f"(sAMAccountName={user_name})", attributes=["distinguishedName"])

    if not conn.entries:
        print("User not found")
        return

    user_dn = conn.entries[0].distinguishedName.value
    conn.search(base_dn, f"(sAMAccountName={group_name})", attributes=["distinguishedName"])

    if not conn.entries:
        print("Group not found")
        return
    group_dn = conn.entries[0].distinguishedName.value

    conn.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})

    if conn.result["result"] == 0:
        print(f"[+] {user_name} added to {group_name}")
    else:
        print(f"[-] Failed:", conn.result)

def add_computer(conn, base_dn, computer_name, password, domain, current_session=None):
    if not computer_name.endswith("$"):
        computer_name += "$"
    computer_cn = computer_name.rstrip("$")
    dn = f"CN={computer_cn},CN=Computers,{base_dn}"

    dns_hostname = f"{computer_cn}.{domain}"

    attributes = {"objectClass": ["top", "person", "organizationalPerson", "user", "computer"], "sAMAccountName": [computer_name], "userAccountControl": ["4096"], "dNSHostname": [dns_hostname]}

    ldaps_enabled = current_session and current_session.get("ldaps", False)
    if ldaps_enabled:
        pwd = f'"{password}"'.encode("utf-16-le")
        attributes["unicodePwd"] = [pwd]

    print(f"[*] Creating computer: {computer_name}")
    print(f"[*] DN: {dn}")

    success = conn.add(dn, attributes=attributes)

    if success:
        print(f"[*] Computer {computer_name} add successfully")
        if not ldaps_enabled and current_session:
            print(f"[*] Setting password via SAMR...")
            try:
                samr_set_password(current_session, computer_name, password)
                print(f"[+] Password set successfully for {computer_name}")
            except Exception as e:
                print(f"[-] Failed to set password via SAMR: {e}")
    else:
        import pprint
        print(f"[-] Failed to add computer : {computer_name}")
        pprint.pprint(conn.result)

def set_password(conn, user_dn, new_password):
    pwd = f'"{new_password}"'.encode("utf-16-le")

    conn.modify(user_dn, {"unicodePwd": [(MODIFY_REPLACE, [pwd])]})

    if conn.result["result"] == 0:
        print("[+] Password changed")
    else:
        print("[-] Failed:", conn.result)

def modify_uac(conn, base_dn, target_user, flag_name, action="add"):
    if flag_name not in UAC_FLAGS:
        print(f"[bold red][-] Unknown UAC flag:[/bold red] {flag_name}")
        print(f"[bold yellow]Available flags:[/bold yellow] {', '.join(UAC_FLAGS.keys())}")
        return False

    flag_val = UAC_FLAGS[flag_name]

    conn.search(base_dn, f"(sAMAccountName={target_user})", attributes=['userAccountControl', 'distinguishedName'])
    if not conn.entries:
        print(f"[bold red][-] Could not find target user {target_user}[/bold red]")
        return False

    entry = conn.entries[0]
    target_dn = entry.distinguishedName.value

    if "userAccountControl" not in entry or entry.userAccountControl.value is None:
        print("[bold red][-] Target does not have a userAccountControl attribute.[/bold red]")
        return False

    current_uac = entry.userAccountControl.value

    if action == "add":
        if current_uac & flag_val:
            print(f"[bold yellow][!] User already has {flag_name} flag set.[/bold yellow]")
            return False
        new_uac = current_uac | flag_val
    elif action == "remove":
        if not (current_uac & flag_val):
            print(f"[bold yellow][!] User does not have {flag_name} flag set.[/bold yellow]")
            return False
        new_uac = current_uac & ~flag_val

    changes = {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]}
    conn.modify(target_dn, changes)

    if conn.result["result"] == 0:
        print(f"[bold green][+] Successfully {action}ed {flag_name} UAC flag for {target_user}[/bold green]")
        return True
    print(f"[bold red][-] Failed to {action} UAC flag: {conn.result['description']}[/bold red]")
    return False

