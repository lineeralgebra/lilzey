from impacket.smbconnection import SMBConnection, SessionError
from rich import print
import os


def _connect(target_ip, username, password, domain, nthash=None):
    """Create and authenticate an SMB connection."""
    try:
        conn = SMBConnection(target_ip, target_ip, timeout=5)
    except Exception as e:
        print(f"[bold red][-] Could not connect to {target_ip}: {e}[/bold red]")
        return None

    try:
        if nthash:
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
            conn.login(username, "", domain, lmhash=lmhash, nthash=nthash)
        else:
            conn.login(username, password, domain)
    except SessionError as e:
        print(f"[bold red][-] Authentication failed: {e}[/bold red]")
        return None

    return conn


def list_shares(target_ip, username, password, domain, nthash=None):
    conn = _connect(target_ip, username, password, domain, nthash)
    if not conn:
        return []

    results = []

    try:
        shares = conn.listShares()
    except SessionError as e:
        print(f"[bold red][-] Could not list shares: {e}[/bold red]")
        conn.close()
        return []

    for share in shares:
        share_name = share["shi1_netname"][:-1]
        share_remark = share["shi1_remark"][:-1]

        can_read = False
        can_write = False

        try:
            conn.listPath(share_name, "*")
            can_read = True
        except SessionError:
            pass

        if can_read:
            test_dir = "\\__ldapshell_write_test__"
            try:
                conn.createDirectory(share_name, test_dir)
                conn.deleteDirectory(share_name, test_dir)
                can_write = True
            except SessionError:
                pass

        results.append({
            "name": share_name,
            "remark": share_remark,
            "read": can_read,
            "write": can_write,
        })

    conn.close()
    return results


def print_shares(shares, target_ip):
    """Print share enumeration results as a formatted table."""
    if not shares:
        print("[bold yellow][!] No shares found or access denied.[/bold yellow]")
        return

    name_w = max(len(s["name"]) for s in shares)
    name_w = max(name_w, 5)
    remark_w = max(len(s["remark"]) for s in shares)
    remark_w = max(remark_w, 6)

    header = f"  {'Share':<{name_w}}   {'Remark':<{remark_w}}   READ   WRITE"
    separator = f"  {'─' * name_w}   {'─' * remark_w}   ────   ─────"

    print(f"\n[bold cyan]SMB Shares on {target_ip}[/bold cyan]")
    print(header)
    print(separator)

    for s in shares:
        r = "[bold green]✓[/bold green]" if s["read"] else "[bold red]✗[/bold red]"
        w = "[bold green]✓[/bold green]" if s["write"] else "[bold red]✗[/bold red]"
        print(f"  {s['name']:<{name_w}}   {s['remark']:<{remark_w}}   {r}      {w}")

    print()


def list_files(target_ip, username, password, domain, share, path="*", nthash=None):
    conn = _connect(target_ip, username, password, domain, nthash)
    if not conn:
        return

    if path != "*" and not path.endswith("\\*") and not path.endswith("/*"):
        path = path.rstrip("\\/") + "\\*"

    display_path = f"\\\\{target_ip}\\{share}" if path == "*" else f"\\\\{target_ip}\\{share}\\{path.rstrip('*').rstrip(chr(92))}"

    try:
        files = conn.listPath(share, path)

        print(f"\n[bold cyan]  Listing: {display_path}[/bold cyan]")
        print(f"  {'Name':30} {'Size':>10}  {'Type'}")
        print(f"  {'─' * 30} {'─' * 10}  {'─' * 5}")

        dirs = []
        regular = []

        for f in files:
            name = f.get_longname()
            if name in (".", ".."):
                continue
            if f.is_directory():
                dirs.append(name)
            else:
                regular.append((name, f.get_filesize()))

        for name in sorted(dirs):
            print(f"  [bold blue]{name:30}[/bold blue] {'':>10}  [bold blue]<DIR>[/bold blue]")

        for name, size in sorted(regular):
            if size >= 1048576:
                size_str = f"{size / 1048576:.1f} MB"
            elif size >= 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} B"
            print(f"  {name:30} {size_str:>10}")

        print(f"\n  [bold green]{len(dirs)} dir(s), {len(regular)} file(s)[/bold green]\n")

    except SessionError as e:
        if "STATUS_NO_SUCH_FILE" in str(e) or "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
            print(f"[bold red][-] Path not found: {display_path}[/bold red]")
        elif "STATUS_BAD_NETWORK_NAME" in str(e):
            print(f"[bold red][-] Share not found: '{share}'. Use 'shares <ip>' to list available shares.[/bold red]")
        elif "STATUS_ACCESS_DENIED" in str(e):
            print(f"[bold red][-] Access denied to: {display_path}[/bold red]")
        else:
            print(f"[bold red][-] Error listing files: {e}[/bold red]")
    except Exception as e:
        print(f"[bold red][-] Error: {e}[/bold red]")

    conn.close()


def download_file(target_ip, username, password, domain, share, remote_path, nthash=None):
    """Download a file from an SMB share."""
    conn = _connect(target_ip, username, password, domain, nthash)
    if not conn:
        return

    remote_path = remote_path.replace("/", "\\")

    local_name = remote_path.split("\\")[-1]

    try:
        with open(local_name, "wb") as f:
            conn.getFile(share, remote_path, f.write)
        print(f"[bold green][+] Downloaded: {share}\\{remote_path} -> ./{local_name}[/bold green]")
    except SessionError as e:
        if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e) or "STATUS_NO_SUCH_FILE" in str(e):
            print(f"[bold red][-] File not found: {share}\\{remote_path}[/bold red]")
        elif "STATUS_ACCESS_DENIED" in str(e):
            print(f"[bold red][-] Access denied: {share}\\{remote_path}[/bold red]")
        else:
            print(f"[bold red][-] Download error: {e}[/bold red]")
        if os.path.exists(local_name) and os.path.getsize(local_name) == 0:
            os.remove(local_name)
    except Exception as e:
        print(f"[bold red][-] Error: {e}[/bold red]")

    conn.close()


def upload_file(target_ip, username, password, domain, share, local_file, nthash=None):
    """Upload a local file to an SMB share."""
    if not os.path.exists(local_file):
        print(f"[bold red][-] Local file not found: {local_file}[/bold red]")
        return

    conn = _connect(target_ip, username, password, domain, nthash)
    if not conn:
        return

    remote_name = local_file.split("/")[-1].split("\\")[-1]

    try:
        with open(local_file, "rb") as f:
            conn.putFile(share, remote_name, f.read)
        print(f"[bold green][+] Uploaded: {local_file} -> {share}\\{remote_name}[/bold green]")
    except SessionError as e:
        if "STATUS_ACCESS_DENIED" in str(e):
            print(f"[bold red][-] Access denied: cannot write to {share}[/bold red]")
        else:
            print(f"[bold red][-] Upload error: {e}[/bold red]")
    except Exception as e:
        print(f"[bold red][-] Error: {e}[/bold red]")

    conn.close()


def main(target_ip, username, password, domain, nthash=None):
    print(f"[bold cyan][*] Enumerating shares on {target_ip} as {domain}\\{username}...[/bold cyan]")
    shares = list_shares(target_ip, username, password, domain, nthash)
    print_shares(shares, target_ip)
