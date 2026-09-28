# Nightward

Runtime security monitor for WordPress. Most security plugins look at files and requests from the outside. Nightward watches what installed plugins and themes actually **do** inside the site, names the file and line that did it, and e-mails you a daily report. Critical findings are e-mailed the moment they happen.

- Version: 1.0.2
- Requires: WordPress 6.2+, PHP 7.4+
- Languages: English, Ukrainian
- Website: https://nightward.muzychenko.dev

## What it watches

| Monitor | What it catches |
|---|---|
| **Outbound requests** | Every `wp_remote_*` call, attributed to plugin/theme file and line. New hosts per plugin, paste sites, tunnels, request-capture services, dynamic DNS, Telegram bot / Discord webhook exfiltration, raw IP addresses, polyfill.io-family domains. |
| **HTTP interception** | Callbacks on `pre_http_request` that fake responses. A sentinel is inserted after every callback, so the exact culprit is known even among several anonymous closures on the same priority. Licence-check bypasses, faked WordPress.org API answers and "intercept everything" callbacks are graded separately. |
| **Sensitive hooks** | Baseline of third-party callbacks on login, capability, user-list, plugin-list, update and mail hooks. New callbacks outside an install/update window are reported. Callbacks compiled with `eval()` / `create_function()` on any hook are critical. |
| **Users & privileges** | Administrators created or promoted by plugin code or by anonymous requests, administrators inserted with raw SQL, administrators hidden from the Users list, admin password/e-mail changed by code, new application passwords, admin logins from new networks. |
| **Options** | Site URL / home, admin e-mail, `default_role`, registration, role capabilities, plugin activation by code, theme switch. Options written on almost every page view (sampled). Autoload weight. |
| **Scheduled tasks** | New cron hooks, random-looking names, PHP / base64 / URLs in arguments, tasks with no handler. |
| **File integrity** | Core against official checksums, WordPress.org plugins against per-version checksums, premium plugins and themes against their own first snapshot (changes without a version bump are reported). Changed files are checked for malware indicators. Runs in batches through WP-Cron. |
| **Executable files** | Scripts in uploads, PHP hidden in images, `.htaccess` / `.user.ini` tricks, unknown PHP in the wp-content root, new must-use plugins, PHP in cache / upgrade / languages. |
| **Update channel** | Where pending and downloaded updates come from. Hijacked WordPress.org updates and known malicious hosts are blocked; packages from hosts unrelated to the vendor can be blocked optionally. |
| **Hardening** | Checked from outside: exposed debug logs, `.env`, `.git`, wp-config backups and dumps, PHP execution in uploads (real test), directory listing, XML-RPC, user enumeration, security headers, HTTPS, wp-config permissions, file editor, PHP version, inactive plugins, WP-Cron health. |

## Reports

- **Daily report** at a configurable local time (default 20:00, site timezone). "All clear" is sent too by default: if the e-mail stops arriving, the site, WP-Cron or Nightward stopped working.
- **Instant alerts** for critical (optionally also high) findings, at the moment of detection, rate-limited per hour; the rest is combined into one message.
- Rendered in the recipient's language when the recipient is a user of the site. Events are stored language-independently and translated when displayed.

## How it starts early

On activation Nightward writes `wp-content/mu-plugins/0-nightward-early.php`, which boots the monitors before regular plugins load. The file is removed on deactivation and can be turned off in Settings.

## What it cannot see

- Requests made with raw cURL, sockets or `file_get_contents()` bypass the WordPress HTTP API.
- Code that runs before Nightward: `wp-config.php`, drop-ins, and must-use plugins loaded earlier.
- Direct database edits are found by the hourly audit, not at the moment they happen.
- Premium plugins/themes are trusted as they are at the first scan.
- It is a detector, not a firewall.

## Learning mode

For the first 24 hours (configurable) new hosts, hooks and scheduled tasks are recorded silently as the baseline. Critical findings are reported regardless.

## For developers

```php
// Fires for every new or re-opened event.
add_action( 'nightward_event', function ( array $event ) {
	// $event: id, module, type, severity, title, details, component, file, line
} );
```

## Translation

`languages/nightward.pot` is the template. `nightward-uk.po/.mo` is the Ukrainian translation.

## Uninstall

Deleting the plugin drops its three tables (`*_nightward_events`, `*_nightward_egress`, `*_nightward_files`), all `nightward_*` options and transients, the per-user network list, the MU loader and scheduled events.
