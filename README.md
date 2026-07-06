# MalScan — Webshell Scanner

Webshell-focused static scanner untuk PHP backdoor + deteksi bypass ekstensi via `.htaccess` (AddHandler PHP → `.js`, FilesMatch, `<Files>` whitelist). Verdict AI opsional via OpenRouter.

## Fitur

- **Webshell-only**: fokus PHP webshell, bukan generic malware
- **Ekstensi default**: `shtml`, `php`, `phar`, `phtml`, `pht`, `php3`, `php4`, `php5`, `php7`, `phtm`, `inc`
- **Parse `.htaccess`**: ekstrak `AddHandler` (PHP/SSI → ekstensi custom), `FilesMatch`, `<Files>` whitelist
- **Disguised webshell**: scan `.js`/ekstensi lain jika di-map ke PHP handler di htaccess
- **PHP signature engine**: eval+superglobal, obfuscation chain, known markers (WSO, China Chopper, c99, dll)
- AI verdict JSON via OpenRouter (mode auto/always/off)
- Single static binary

## Build

```powershell
cargo build --release
# atau
.\build.ps1
```

Cross-compile Linux:

```powershell
.\build.ps1 -Target x86_64-unknown-linux-gnu -Output malscan
```

## Penggunaan

```bash
# Scan webroot — otomatis baca .htaccess untuk ekstensi custom
malscan scan ./public_html --ai-mode off

# Tambah ekstensi manual
malscan scan ./site --ext js,txt --ai-mode off

# JSON report
malscan scan ./tests/samples -f json -q
```

## Output otomatis (`.malscan/`)

Setiap scan menulis report terpisah per verdict ke `{target}/.malscan/`:

```
.malscan/
  clean.json / clean.txt
  suspicious.json / suspicious.txt
  malicious.json / malicious.txt
  summary.json
```

- Lokasi: folder target scan (atau parent jika target single file)
- File `.malscan/` selalu JSON + TXT; flag `-f` hanya untuk stdout / `-o`
- Folder `.malscan/` di-skip saat scan recursive
- `-o report.json` opsional untuk export gabungan tambahan

## .htaccess Detection

Scanner parse directive seperti:

```apache
<FilesMatch "(?i).*(shtml|php|phar|phtml|pht).*"> ... </FilesMatch>
<Files jsws2.php> Allow from all </Files>
AddHandler application/x-httpd-php .js
```

Hasil:
- Ekstensi `.js` ditambahkan ke scan scope (PHP handler disguise)
- `jsws2.php` di-flag sebagai whitelisted PHP file
- Hit signature: `htaccess:php_handler_disguise`, `htaccess:allowed_php_file`

File non-webshell (`.txt`, `.exe`, PowerShell, dll) **di-skip** kecuali mengandung marker PHP.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean |
| 1 | Suspicious |
| 2 | Malicious |

## API Key

Wajib via env var atau flag `--api-key`:

```powershell
$env:OPENROUTER_API_KEY = "your-key-here"
malscan scan ./site --ai-mode auto

# atau
malscan scan ./site --ai-mode auto --api-key "your-key-here"
```

## Testing

```bash
cargo test
```

## Keamanan

- Scanner **tidak mengeksekusi** file target
- Feature summary dikirim ke OpenRouter saat AI mode aktif
- Jangan commit API key ke repo; gunakan env var

## Lisensi

MIT
