# Nightward

Runtime security monitor for WordPress. Most security plugins look at files and requests from the outside. Nightward watches what installed plugins and themes actually **do** inside the site, names the file and line that did it, and e-mails you a daily report. Critical findings are e-mailed the moment they happen.

- Version: 1.1.8
- Requires: WordPress 6.2+, PHP 7.4+
- Languages: English, Ukrainian
- Website: https://nightward.muzychenko.dev

## What it watches

| Monitor | What it catches |
|---|---|
| **Outbound requests** | Every `wp_remote_*` call, attributed to plugin/theme file and line. New hosts per plugin, paste sites, tunnels, request-capture services, dynamic DNS, Telegram bot / Discord webhook exfiltration, raw IP addresses, polyfill.io-family domains. |
| **HTTP interception** | Callbacks on `pre_http_request` that fake responses. A sentinel is inserted after every callback, so the exact culprit is known even among several anonymous closures on the same priority. Licence-check bypasses (by URL or by a fake body such as `"license":"valid"`), faked WordPress.org API answers and "intercept everything" callbacks are graded separately. |
| **Sensitive hooks** | Baseline of third-party callbacks on login, capability, user-list, plugin-list, update and mail hooks. New callbacks outside an install/update window are reported. Callbacks compiled with `eval()` / `create_function()` on any hook are critical. |
| **Users & privileges** | Administrators created or promoted by plugin code or by anonymous requests, administrators inserted with raw SQL, administrators hidden from the Users list, admin password/e-mail changed by code, new application passwords, admin logins from new networks. |
| **Options** | Site URL / home, admin e-mail, `default_role`, registration, role capabilities, plugin activation by code, theme switch. Options written on almost every page view (sampled). Autoload weight. |
| **Scheduled tasks** | New cron hooks, random-looking names, PHP / base64 / URLs in arguments, tasks with no handler (WordPress core tasks are recognised even when their handler is attached only in some requests). |
| **File integrity** | Core against official checksums, WordPress.org plugins against per-version checksums, premium plugins and themes against their own first snapshot (changes without a version bump are reported). Changed files are checked for malware indicators. Runs in batches through WP-Cron. |
| **Executable files** | Scripts in uploads; PHP or a PHAR stub anywhere in an image (whole file up to 2 MB, head and tail of larger ones); files with an image extension whose content is not an image; `.htaccess` / `.user.ini` tricks; unknown PHP in the wp-content root; new must-use plugins; PHP in cache / upgrade / languages. Uploads are walked in a fixed order with a cursor, so large media libraries are fully checked across runs. One finding per file, even when the file keeps changing. |
| **Update channel** | Where pending and downloaded updates come from (entries written under an empty key are matched to their plugin by slug or vendor host; findings close when the update is no longer offered). Hijacked WordPress.org updates and known malicious hosts are blocked; packages from hosts unrelated to the vendor can be blocked optionally. |
| **Hardening** | Checked from outside: exposed debug logs, `.env`, `.git`, wp-config backups and dumps, PHP execution in uploads (real test), directory listing, XML-RPC login (a real login call with empty credentials: switched off, blocked or open), user enumeration, security headers, HTTPS, wp-config permissions, file editor, PHP version, inactive plugins, WP-Cron health. |

## Events

- The **Events** tab lists findings from critical to low by default (switchable to most recent first). Informational records (plugins activated or removed, scans finished) are on a separate **Log** tab.
- A finding re-assessed as more serious after an update is reopened and reported again.

## Reports

- **Daily report** at a configurable local time (default 20:00, site timezone). "All clear" is sent too by default: if the e-mail stops arriving, the site, WP-Cron or Nightward stopped working. One report per occurrence: a second run within 30 minutes (WP-Cron and the backup scheduler starting in the same visit, a manual run) is stopped and counted on the overview.
- **Instant alerts** for critical (optionally also high) findings, at the moment of detection, rate-limited per hour; the rest is combined into one message.
- Rendered in the recipient's language when the recipient is a user of the site. Events are stored language-independently and translated when displayed.

## When WP-Cron does not run

Reports and scans are WP-Cron tasks. When tasks have been waiting for more than an hour, the overview shows a **WP-Cron** panel:

- what is waiting and when WP-Cron last really ran;
- **Start and check WP-Cron** starts WP-Cron exactly the way WordPress does (same lock, same URL filters) and waits until WordPress reports from inside, so waiting tasks really run. It names the cause: the server unable to reach its own address, a redirect, password protection, a firewall or maintenance page, an answer with no WordPress behind it (a firewall that runs first via `auto_prepend_file`, a server rule), a lock that does not survive between requests (object cache);
- it also records WordPress's own start attempts and whether they ever reach `wp-cron.php`, which catches background requests dropped by a proxy or CDN, `DISABLE_WP_CRON` without a server job and a removed `wp_cron` hook;
- each `wp-cron.php` request records how far it got, so a fatal error (with message, plugin, file and line), an `exit` during loading (attributed to the plugin being loaded, or to the hook, priority and callbacks running at that moment, with the server IP to allow in its firewall) and a PHP process killed after the answer was sent (LiteSpeed `noabort`, with the `.htaccess` fix) are told apart;
- every write or deletion of the WP-Cron lock (`doing_cron` transient) is attributed to the plugin file and line that made it, so a plugin that keeps resetting the lock, or a cache that hides it from the next request, is named;
- ready-made server cron lines (`curl`, `wget`, WP-CLI) with the site's real address and path.

Until it is fixed, the **backup scheduler** runs Nightward's own overdue tasks (report, hourly checks, scans) during ordinary requests, after the response has been sent where PHP-FPM or LiteSpeed allows it. Heavy scans otherwise wait for a dashboard Heartbeat request. Nightward also recreates its own scheduled tasks if another plugin or a person removes them. Turn the backup scheduler off in Settings → Advanced.

## Export for AI analysis

**Nightward → AI export** builds one file you can paste into ChatGPT, Claude, Gemini or any other assistant:

- instructions for the assistant (what Nightward is, how to read the file, how to triage, which language to answer in), so you only ask your question;
- site context, findings with severity, file and line, and all recorded details;
- optional inventory: installed plugins and themes, outbound hosts, callbacks on sensitive hooks, scheduled tasks;
- hardening and file integrity results.

Markdown (best for chat) or JSON. Filters for period, status and minimum severity. The site address, e-mail and IP addresses are masked by default. Credentials are never exported, see below. Download the file or copy it to the clipboard.

From the command line:

```
wp nightward export > nightward.md
wp nightward export --format=json --days=7 --min-severity=high --file=report.json
```

## How it starts early

On activation Nightward writes `wp-content/mu-plugins/0-nightward-early.php`, which boots the monitors before regular plugins load. The file is removed on deactivation and can be turned off in Settings.

## What it cannot see

- Requests made with raw cURL, sockets or `file_get_contents()` bypass the WordPress HTTP API.
- Code that runs before Nightward: `wp-config.php`, drop-ins, and must-use plugins loaded earlier.
- Direct database edits are found by the hourly audit, not at the moment they happen.
- Premium plugins/themes are trusted as they are at the first scan.
- It is a detector, not a firewall.

## Credentials are never stored

Every URL and detail is cleaned before it is written to the database: Telegram bot tokens (`/bot<id>:…`, the bot ID stays), Discord and Slack webhook secrets, `user:pass@` in URLs and the values of secret query parameters (`token`, `key`, `api_key`, `secret`, `password`, `license_key`, `signature` and similar). Hosts, paths and IDs stay for attribution. Records written by earlier versions are cleaned once after the update. `--no-redact` and the export switch only reveal the site address, e-mail and IP addresses.

## Removed plugins and themes

When a plugin or theme is deleted, its findings that existed only while the code was installed (requests, interception, hooks, file changes, update channel, option writes) are deleted with its outbound statistics and file snapshot. Administrators, scheduled tasks and files it left behind keep their findings until they are gone too. Removals outside the dashboard are noticed when the Plugins or Themes screen opens, and daily.

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
