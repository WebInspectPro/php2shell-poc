# php2shell-poc
CLI scanner and PoC for CVE-2026-109618 / CVE-2026-109619 (PHP OOM heap corruption and session upload-progress injection, CVSS 9.2). Affects PHP 5.4.0-8.5.11; patched in 8.2.35, 8.3.36, 8.4.27, 8.5.12. 

# php2shell.py

CLI scanner and PoC for CVE-2026-109618 and CVE-2026-109619.

**Affected Versions:** PHP 5.4.0 through 8.5.11  
**Patched Versions:**  PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35 (see note below on 8.4.27 and 8.5.12)  
**CVSS:** 9.2 (both CVEs)  
**Advisory numbers:** Ubuntu USN-8948-1/2, Debian DSA-6574-1, Red Hat RHSA-2026:87072

Web-based checker: [webinspect.pro/Tools/php2shell.php](https://webinspect.pro/Tools/php2shell.php)  
Full technical reference: [php2shell-how-it-works.php](https://webinspect.pro/Tools/php2shell-how-it-works.php)

---

## Requirements

Python 3.8+. No external dependencies; stdlib only.

---

## Usage

```
python3 php2shell.py <domain> [options]

  (no flags)  Recon only: version detection, phpinfo probe, phpMyAdmin check,
              multipart POST acceptance. No crash attempt, no session write.
  --poc       Run all PoC steps (crash probe + inject demo + GH-24488 check)
  --crash     CVE-2026-109618: OOM crash probe only
  --inject    CVE-2026-109619: session injection demo only
  --zero2     Check GH-24488: GC double-free in PHP 8.4.27 and 8.5.12 (version-based)
  --https     Force HTTPS (skip auto-detection)
  --json      Machine-readable JSON output
  --timeout   Per-request timeout in seconds (default: 15)
```

**Recon only:**
```bash
python3 php2shell.py example.com
```

**Recon + all PoC steps:**
```bash
python3 php2shell.py example.com --poc
```

**JSON output (for piping or tooling):**
```bash
python3 php2shell.py example.com --poc --json | jq .
```

---

## What does it check:

**Always:**
- PHP version from `X-Powered-By`, `Server` headers, and PHP error pages
- Exposed phpinfo pages (19 common paths)
- phpMyAdmin endpoint (`/show_config_errors.php`) (confirmed exploitation path)
- Multipart POST acceptance on `/index.php` (direct gate for the CVE-2026-109619 chain)

**When a phpinfo page is found:**
- SAPI and server software (Apache, Nginx, FrankenPHP, LiteSpeed all affected)
- `session.upload_progress.enabled` and `.cleanup`
- `session.serialize_handler` (mismatch enables CVE-2026-115560)
- `session.use_strict_mode`, `session.use_only_cookies`
- `memory_limit`, `max_input_vars`, `post_max_size`
- `open_basedir`, `disable_functions` (with Chain B caveat)
- `fatal_error_backtraces` (PHP 8.5+: stack traces on fatal errors can leak heap metadata)
- `display_errors`, `allow_url_include`, `file_uploads`

---

## PoC steps

### CVE-2026-109618: OOM crash probe (`--crash`)

PHP's multipart parser (`rfc1867.c`) recurses when it encounters a part with `Content-Type: multipart/*`. Each recursive call allocates a buffer on the PHP heap. This PoC sends a 200-level nested multipart body. When the cumulative allocation exceeds `memory_limit`, PHP aborts mid-request with a heap corruption fatal or an empty 500 response.

A crash is confirmed by an OOM string in the response body (`Allowed memory size`, `zend_mm_heap corrupted`) or a near-empty HTTP 500 (under ~300 bytes).

### CVE-2026-109619: session injection demo (`--inject`)

When `session.upload_progress.enabled` is `On` (the PHP default since 5.4), any multipart POST containing the field `PHP_SESSION_UPLOAD_PROGRESS` causes PHP to write a serialized array to the session store **before any application code runs**. The `name` attribute of the uploaded file is stored verbatim inside that array:

```
$_SESSION["upload_progress_<key>"] = [
    "files" => [
        ["name" => "<ATTACKER CONTROLLED>", ...]
    ]
]
```

This demo sends a benign marker as the filename and confirms whether the write primitive is reachable. **It does not trigger deserialization.** In a real attack the filename field carries a serialized PHP object; with a `session.serialize_handler` mismatch (CVE-2026-115560), the object is deserialized on the next session read, completing the RCE chain.

---

## Mitigations

| Setting | Recommended value | Effect |
|---|---|---|
| `session.upload_progress.enabled` | `Off` in `php.ini` | Closes Chains A, C, E. Must be in `php.ini`; `.user.ini` runs too late. |
| `session.serialize_handler` | `php_serialize` (consistent) | Closes CVE-2026-115560 mismatch path. |
| `session.save_path` | Outside document root | Prevents direct session file access. |
| `memory_limit` | As low as the application allows | Reduces OOM window. |
| PHP version | 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 | Patches CVE-2026-109618 and CVE-2026-109619. |

**Note on patched versions and post-patch regressions:**

PHP 8.4.27 and 8.5.12 patch CVE-2026-109618/CVE-2026-109619 but introduced a GC double-free regression (GH-24488, filed as php/php-src issue #24488). The fix was merged Oct 22 2026; pending release in 8.4.28 and 8.5.13. Mitigation: `zend.enable_gc = Off` in php.ini until the fix ships. PHP 8.3.36 and 8.2.35 are not affected by this regression.

**CVE-2026-115560** (session serialize_handler mismatch) was acknowledged by PHP on Oct 23 2026 and is not yet patched. It requires a specific combination: `session.serialize_handler` set to `php_binary` or `php_serialize` in php.ini, and a runtime `ini_set()` call that switches the handler to `php` before `session_start()`. The default handler (`php`) is not affected through this path. Mitigation: `session.upload_progress.enabled = Off` in php.ini. Configuration hardening is recommended regardless of patch status.

**Note on `disable_functions`:** Chain B (var_destroy use-after-free) dispatches below PHP's function-level checks and bypasses `disable_functions` entirely. A populated list constrains Chains A, C, and E but not B.

---

## Detection indicators

None of these are visible remotely. Useful if you're monitoring infrastructure you control.

**Access logs:**
- Multipart POST to any PHP endpoint with `PHP_SESSION_UPLOAD_PROGRESS` in the body
- Rapid sequence of multipart POSTs from the same IP (upload-progress race)
- HTTP 500 responses immediately following an oversized multipart POST (OOM trigger)
- `memory exhausted` or `zend_mm_heap corrupted` in PHP error log

**Session storage:**
- Session files (`sess_*`) containing `upload_progress_` keys with `O:` markers (serialized object notation)
- Zero-byte session files (truncated by OOM mid-write)

**System logs:**
- `double free or corruption` / `tcache double free detected` (heap corruption)
- Web server spawning unexpected child processes or outbound connections

---

## Legal notice

Use only against systems you own or have explicit written permission to test. Standard jurisdictional laws apply (CFAA, CMA, etc.).
