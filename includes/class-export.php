<?php
/**
 * Export for AI analysis.
 *
 * Builds one self-contained file (Markdown or JSON) with everything an AI
 * assistant needs to review the site's security state: instructions for the
 * assistant, site context, findings with evidence, installed packages,
 * outbound hosts, sensitive hooks, scheduled tasks, hardening and integrity.
 *
 * Findings are exported in English (the language they are stored in); the
 * instructions tell the assistant which language to answer in.
 */

namespace Nightward;

use Nightward\Monitor\Cron_Guard;
use Nightward\Monitor\Hooks_Watch;
use Nightward\Monitor\Outbound;
use Nightward\Scanner\Hardening;
use Nightward\Scanner\Integrity;

defined( 'ABSPATH' ) || exit;

class Export {

	const FORMAT_VERSION = 1;
	const MAX_FINDINGS   = 500;

	private static $redact = true;
	private static $hosts  = array();

	public static function defaults() {
		return array(
			'format'       => 'md',       // md | json
			'days'         => 30,         // 0 = all time
			'status'       => 'active',   // active (open + acknowledged) | all
			'min_severity' => 'low',
			'inventory'    => 1,
			'redact'       => 1,
		);
	}

	public static function sanitize( array $in ) {
		$d   = self::defaults();
		$out = array(
			'format'       => isset( $in['format'] ) && 'json' === $in['format'] ? 'json' : 'md',
			'days'         => isset( $in['days'] ) ? max( 0, min( 3650, (int) $in['days'] ) ) : $d['days'],
			'status'       => isset( $in['status'] ) && 'all' === $in['status'] ? 'all' : 'active',
			'min_severity' => isset( $in['min_severity'] ) && in_array( $in['min_severity'], Events::SEVERITIES, true ) ? $in['min_severity'] : $d['min_severity'],
			'inventory'    => empty( $in['inventory'] ) ? 0 : 1,
			'redact'       => empty( $in['redact'] ) ? 0 : 1,
		);
		return $out;
	}

	public static function filename( array $opt ) {
		$host = self::$redact ? 'site' : preg_replace( '/[^a-z0-9.-]/i', '', (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		return 'nightward-' . $host . '-' . gmdate( 'Y-m-d-His' ) . ( 'json' === $opt['format'] ? '.json' : '.md' );
	}

	/* ------------------------------------------------------------------ */
	/* Redaction                                                           */
	/* ------------------------------------------------------------------ */

	private static function init_redaction( $on ) {
		self::$redact = (bool) $on;
		self::$hosts  = array_values( array_unique( array_filter( array(
			Util::host_of( home_url() ),
			Util::host_of( site_url() ),
		) ) ) );
	}

	/** Mask site address, e-mail addresses and IP addresses. */
	public static function clean( $s ) {
		if ( ! is_string( $s ) || '' === $s || ! self::$redact ) {
			return $s;
		}
		foreach ( self::$hosts as $h ) {
			$s = str_ireplace( $h, 'example-site.test', $s );
		}
		$s = preg_replace_callback( '/([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/', function ( $m ) {
			$domain = strtolower( $m[2] );
			$keep   = in_array( $domain, array( 'example-site.test' ), true ) ? $domain : '***.' . substr( strrchr( $domain, '.' ), 1 );
			return $m[1] . '***@' . $keep;
		}, $s );
		$s = preg_replace( '/\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b/', '$1.x.x', $s );
		return $s;
	}

	/** Stored value (string or array(format, ...args)) as English text. */
	private static function plain( $v ) {
		if ( is_array( $v ) ) {
			$v   = array_map( array( 'Nightward\\Events', 'english' ), array_map( 'strval', array_values( $v ) ) );
			$fmt = (string) array_shift( $v );
			$out = @vsprintf( $fmt, $v ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return self::clean( false === $out ? $fmt : $out );
		}
		return self::clean( (string) Events::english( (string) $v ) );
	}

	/* ------------------------------------------------------------------ */
	/* Data                                                                */
	/* ------------------------------------------------------------------ */

	public static function build( array $opt ) {
		$opt = self::sanitize( $opt );
		self::init_redaction( $opt['redact'] );
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$args = array(
			'min_severity' => $opt['min_severity'],
			'limit'        => self::MAX_FINDINGS,
			'order'        => 'severity',
		);
		if ( 'active' === $opt['status'] ) {
			$args['status'] = array( 'open', 'acknowledged' );
		}
		if ( $opt['days'] ) {
			$args['since'] = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS * $opt['days'] );
		}
		$rows = Events::query( $args );

		$findings = array();
		$by       = array_fill_keys( Events::SEVERITIES, 0 );
		foreach ( $rows as $r ) {
			$by[ $r->severity ]++;
			$d       = Events::details( $r );
			$explain = isset( $d['explanation'] ) ? self::plain( $d['explanation'] ) : '';
			$extra   = array();
			foreach ( $d as $k => $v ) {
				if ( in_array( $k, array( 'explanation', '_t', 'user_id' ), true ) || '' === $v || null === $v || array() === $v ) {
					continue;
				}
				if ( is_bool( $v ) ) {
					$v = $v ? 'yes' : 'no';
				} elseif ( is_array( $v ) ) {
					$v = implode( ', ', array_map( function ( $x ) {
						return is_scalar( $x ) ? (string) $x : wp_json_encode( $x );
					}, $v ) );
				}
				$extra[ $k ] = self::clean( (string) Events::english( (string) $v ) );
			}
			$findings[] = array(
				'id'          => (int) $r->id,
				'severity'    => $r->severity,
				'area'        => $r->module,
				'type'        => $r->type,
				'title'       => self::plain( ! empty( $d['_t'] ) ? $d['_t'] : $r->title ),
				'explanation' => $explain,
				'component'   => $r->component ? $r->component : null,
				'component_name' => $r->component ? self::clean( wp_strip_all_tags( Attribution::label( $r->component ) ) ) : null,
				'file'        => $r->file ? $r->file : null,
				'line'        => $r->line ? (int) $r->line : null,
				'status'      => $r->status,
				'hits'        => (int) $r->hits,
				'first_seen'  => $r->first_seen . ' UTC',
				'last_seen'   => $r->last_seen . ' UTC',
				'details'     => $extra,
			);
		}

		$data = array(
			'format'       => 'nightward-export',
			'format_version' => self::FORMAT_VERSION,
			'generated'    => gmdate( 'Y-m-d H:i' ) . ' UTC',
			'instructions' => self::instructions(),
			'scope'        => array(
				'period'       => $opt['days'] ? sprintf( 'last %d days', $opt['days'] ) : 'all time',
				'statuses'     => 'active' === $opt['status'] ? 'open and acknowledged' : 'all (including resolved and ignored)',
				'min_severity' => $opt['min_severity'],
				'redacted'     => (bool) $opt['redact'],
				'truncated'    => count( $rows ) >= self::MAX_FINDINGS,
			),
			'site'         => self::site(),
			'summary'      => array(
				'findings_by_severity' => $by,
				'open_by_severity'     => Events::open_counts(),
			),
			'findings'     => $findings,
		);

		if ( $opt['inventory'] ) {
			$data['packages']        = self::packages();
			$data['outbound_hosts']  = self::egress();
			$data['sensitive_hooks'] = self::hooks();
			$data['scheduled_tasks'] = self::cron();
		}
		$data['hardening'] = self::hardening();
		$data['integrity'] = self::integrity();
		return $data;
	}

	private static function site() {
		global $wp_version;
		$h     = Cron::health();
		$mail  = get_option( 'nightward_mail_status' );
		$user  = wp_get_current_user();
		return array(
			'address'            => self::$redact ? 'https://example-site.test' : home_url( '/' ),
			'wordpress'          => $wp_version,
			'php'                => PHP_VERSION,
			'multisite'          => is_multisite(),
			'site_language'      => get_locale(),
			'admin_language'     => $user && $user->ID ? get_user_locale( $user ) : get_locale(),
			'nightward'          => NIGHTWARD_VERSION,
			'nightward_installed' => gmdate( 'Y-m-d', (int) get_option( 'nightward_installed_at', time() ) ),
			'learning_mode'      => Settings::in_learning(),
			'wp_cron_running'    => ! $h['stale'],
			'wp_cron_waiting'    => $h['overdue']['count'] ? $h['overdue']['count'] . ' task(s), oldest due ' . human_time_diff( $h['overdue']['oldest'] ) . ' ago: ' . implode( ', ', $h['overdue']['hooks'] ) : 'none',
			'disable_wp_cron'    => $h['disabled'],
			'last_report_email'  => is_array( $mail ) ? ( $mail['ok'] ? 'sent' : 'failed' ) : 'none yet',
			'early_loader'       => Installer::loader_installed(),
			'modules_disabled'   => array_values( array_filter( array( 'outbound', 'hooks', 'privilege', 'options', 'cron', 'integrity', 'uploads', 'update_channel', 'hardening' ), function ( $m ) {
				return ! Settings::enabled( $m );
			} ) ),
		);
	}

	private static function packages() {
		$out    = array();
		$active = (array) get_option( 'active_plugins', array() );
		$net    = is_multisite() ? array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) : array();
		foreach ( get_plugins() as $file => $p ) {
			$out[] = array(
				'type'       => 'plugin',
				'name'       => $p['Name'],
				'slug'       => false === strpos( $file, '/' ) ? preg_replace( '/\.php$/', '', $file ) : strtok( $file, '/' ),
				'version'    => $p['Version'],
				'active'     => in_array( $file, $active, true ) || in_array( $file, $net, true ),
				'author'     => wp_strip_all_tags( $p['Author'] ),
				'plugin_uri' => $p['PluginURI'],
				'update_uri' => isset( $p['UpdateURI'] ) ? $p['UpdateURI'] : '',
			);
		}
		foreach ( (array) get_mu_plugins() as $file => $p ) {
			$out[] = array( 'type' => 'mu-plugin', 'name' => $p['Name'] ? $p['Name'] : $file, 'slug' => $file, 'version' => $p['Version'], 'active' => true, 'author' => wp_strip_all_tags( $p['Author'] ), 'plugin_uri' => $p['PluginURI'], 'update_uri' => '' );
		}
		foreach ( (array) get_dropins() as $file => $p ) {
			$out[] = array( 'type' => 'drop-in', 'name' => $file, 'slug' => $file, 'version' => $p['Version'], 'active' => true, 'author' => wp_strip_all_tags( $p['Author'] ), 'plugin_uri' => '', 'update_uri' => '' );
		}
		$stylesheet = get_stylesheet();
		$template   = get_template();
		foreach ( wp_get_themes() as $slug => $t ) {
			$out[] = array(
				'type'       => 'theme',
				'name'       => $t->get( 'Name' ),
				'slug'       => $slug,
				'version'    => $t->get( 'Version' ),
				'active'     => $slug === $stylesheet || $slug === $template,
				'author'     => wp_strip_all_tags( $t->get( 'Author' ) ),
				'plugin_uri' => $t->get( 'ThemeURI' ),
				'update_uri' => $t->get( 'UpdateURI' ),
			);
		}
		return $out;
	}

	private static function egress() {
		$out = array();
		foreach ( Outbound::rows( 30, 200 ) as $r ) {
			$out[] = array(
				'host'        => self::clean( $r->host ),
				'requested_by' => self::clean( wp_strip_all_tags( Attribution::label( $r->component ) ) ),
				'component'   => $r->component,
				'requests'    => (int) $r->hits,
				'faked'       => (int) $r->intercepted,
				'errors'      => (int) $r->errors,
				'first_seen'  => $r->first_seen . ' UTC',
				'last_seen'   => $r->last_seen . ' UTC',
				'sample_url'  => self::clean( $r->sample_url ),
			);
		}
		return $out;
	}

	private static function hooks() {
		$out = array();
		foreach ( Hooks_Watch::current_map() as $group => $list ) {
			foreach ( $list as $i ) {
				$out[] = array(
					'group'     => $group,
					'hook'      => $i['hook'],
					'component' => $i['component'],
					'callback'  => $i['name'],
					'location'  => $i['file'] . ':' . $i['line'],
					'priority'  => $i['priority'],
				);
			}
		}
		return $out;
	}

	private static function cron() {
		$out = array();
		foreach ( Cron_Guard::table() as $r ) {
			if ( 'core' === $r['component'] ) {
				continue;
			}
			$out[] = array(
				'hook'       => $r['hook'],
				'recurrence' => $r['schedule'] ? $r['schedule'] : 'single',
				'next_run'   => gmdate( 'Y-m-d H:i', $r['next'] ) . ' UTC',
				'handler'    => 'none' === $r['component'] ? 'no handler attached' : $r['handler'] . ' (' . $r['file'] . ':' . $r['line'] . ')',
				'component'  => $r['component'],
				'random_name' => $r['random'],
				'suspicious_args' => $r['bad_args'] ? $r['bad_args'] : null,
			);
		}
		return $out;
	}

	private static function hardening() {
		$r = Hardening::results();
		if ( ! $r ) {
			return array( 'checked' => null, 'score' => null, 'checks' => array() );
		}
		$checks = array();
		foreach ( $r['results'] as $x ) {
			$checks[] = array(
				'status'   => $x['status'],
				'severity' => $x['sev'] ? $x['sev'] : null,
				'check'    => self::plain( $x['title'] ),
				'detail'   => $x['detail'] ? self::plain( $x['detail'] ) : null,
				'fix'      => $x['fix'] ? self::plain( $x['fix'] ) : null,
			);
		}
		return array( 'checked' => gmdate( 'Y-m-d H:i', $r['at'] ) . ' UTC', 'score' => Hardening::score(), 'checks' => $checks );
	}

	private static function integrity() {
		$st   = Integrity::status();
		$last = $st['last'];
		$out  = array( 'last_scan' => null, 'files_checked' => null, 'problems' => null, 'packages' => array() );
		if ( $last ) {
			$out['last_scan']     = gmdate( 'Y-m-d H:i', $last['finished'] ) . ' UTC';
			$out['files_checked'] = (int) $last['files'];
			$out['problems']      = (int) $last['problems'];
			$labels = array( 'core' => 'official WordPress checksums', 'wporg' => 'official WordPress.org checksums', 'tofu' => 'own snapshot from the first scan', 'baseline' => 'snapshot just taken' );
			foreach ( (array) $last['verified'] as $pkg => $mode ) {
				$out['packages'][ $pkg ] = isset( $labels[ $mode ] ) ? $labels[ $mode ] : $mode;
			}
		}
		return $out;
	}

	/* ------------------------------------------------------------------ */
	/* Instructions for the assistant                                      */
	/* ------------------------------------------------------------------ */

	private static function language_name( $locale ) {
		$names = array( 'uk' => 'Ukrainian', 'en' => 'English', 'pl' => 'Polish', 'de' => 'German', 'fr' => 'French', 'es' => 'Spanish', 'it' => 'Italian', 'pt' => 'Portuguese', 'cs' => 'Czech', 'nl' => 'Dutch', 'ro' => 'Romanian', 'tr' => 'Turkish', 'ja' => 'Japanese', 'zh' => 'Chinese', 'ru' => 'Russian' );
		$code  = strtolower( substr( (string) $locale, 0, 2 ) );
		return isset( $names[ $code ] ) ? $names[ $code ] : $locale;
	}

	public static function instructions() {
		$user = wp_get_current_user();
		$lang = self::language_name( $user && $user->ID ? get_user_locale( $user ) : get_locale() );
		return implode( "\n", array(
			'You are a WordPress security analyst. This file is an export from Nightward, a WordPress plugin that monitors what installed plugins and themes actually do while the site runs, and attributes each finding to the plugin file and line responsible. The site owner uploaded it so you can review the site\'s security state. Everything you need is in this file.',
			'',
			'How to read it:',
			'- "findings" are events recorded by Nightward, most serious first. Each has a severity, an area (module), a title, an explanation written by Nightward, the component responsible (plugin:slug, theme:slug, mu:file, dropin:file, core, or eval = code compiled at runtime with eval()), file and line when known, how many times it was seen, and module-specific details.',
			'- Severity: critical = signs of compromise or a change that gives someone control; high = likely a problem but legitimate explanations exist; medium = worth checking; low = changes worth knowing; info = context only.',
			'- Status: open = new; acknowledged = the owner has seen it; resolved = fixed (listed only if the export includes all statuses); ignored = marked as expected by the owner.',
			'- Areas: outbound = HTTP requests made by plugins; interception = code that answered an HTTP request itself (pre_http_request), for example faking a licence check; hooks = callbacks on login, capability, user-list, plugin-list, update and mail hooks; privilege = administrators and credentials; options = critical site settings; cron = scheduled tasks; integrity = files compared with official checksums or with Nightward\'s own first snapshot; uploads = executable files where they must not be; update_channel = where plugin updates come from; hardening = server configuration checked from outside.',
			'- "packages", "outbound_hosts", "sensitive_hooks" and "scheduled_tasks" describe the current state of the site. Use them to confirm or dismiss findings.',
			'- If "redacted" is true, the site address was replaced with example-site.test and e-mail and IP addresses were masked. Do not treat the placeholders as suspicious.',
			'',
			'What to do:',
			'1. Start with a short verdict: is there evidence that the site is compromised, and how confident are you.',
			'2. Group the findings: (a) likely compromise or malicious behaviour, (b) risky but explainable, (c) configuration and hardening, (d) expected behaviour or noise. Justify every placement with evidence from this file.',
			'3. For each finding in (a) and (b): explain in plain language what the code did, why it matters, and what exactly to check (plugin, file, line). Give concrete remediation steps in WordPress terms.',
			'4. Look for connections across areas. The same component appearing in several areas (for example interception plus a new administrator plus a scheduled task) is much more serious than any single finding.',
			'5. Judge components by their behaviour, not by their name or popularity. A premium plugin faking its own licence check is typical of pirated ("nulled") copies; say so when the evidence points there.',
			'6. When you need the contents of a file to decide, ask the owner for that specific file by its path, one file at a time.',
			'7. Nightward cannot see: requests made with raw cURL or sockets, code that runs before it loads (wp-config.php, drop-ins, earlier must-use plugins), direct database changes at the moment they happen. Mention these blind spots only when they matter for a conclusion.',
			'8. Be direct and specific. Skip generic advice (backups, strong passwords, keep everything updated) unless it follows from a finding.',
			'9. Answer in ' . $lang . '.',
		) );
	}

	/* ------------------------------------------------------------------ */
	/* Rendering                                                           */
	/* ------------------------------------------------------------------ */

	public static function render( array $data, $format ) {
		if ( 'json' === $format ) {
			return wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR ) . "\n";
		}
		return self::markdown( $data );
	}

	private static function md( $s ) {
		return str_replace( array( "\r", "\n", '|' ), array( '', ' ', '\\|' ), (string) $s );
	}

	private static function markdown( array $d ) {
		$L   = array();
		$L[] = '# Nightward security export';
		$L[] = '';
		$L[] = 'Generated ' . $d['generated'] . ' by Nightward ' . $d['site']['nightward'] . '. Scope: ' . $d['scope']['period'] . ', ' . $d['scope']['statuses'] . ', severity ' . $d['scope']['min_severity'] . ' and above' . ( $d['scope']['redacted'] ? ', site address, e-mails and IPs masked' : '' ) . ( $d['scope']['truncated'] ? ', truncated to ' . self::MAX_FINDINGS . ' findings' : '' ) . '.';
		$L[] = '';
		$L[] = '## Instructions for the AI assistant';
		$L[] = '';
		$L[] = $d['instructions'];
		$L[] = '';
		$L[] = '## Site';
		$L[] = '';
		foreach ( $d['site'] as $k => $v ) {
			if ( is_bool( $v ) ) {
				$v = $v ? 'yes' : 'no';
			} elseif ( is_array( $v ) ) {
				$v = $v ? implode( ', ', $v ) : 'none';
			}
			$L[] = '- ' . str_replace( '_', ' ', $k ) . ': ' . $v;
		}
		$L[] = '';
		$L[] = '## Summary';
		$L[] = '';
		$parts = array();
		foreach ( $d['summary']['findings_by_severity'] as $s => $n ) {
			$parts[] = $s . ' ' . $n;
		}
		$L[] = '- Findings in this export: ' . count( $d['findings'] ) . ' (' . implode( ', ', $parts ) . ')';
		$parts = array();
		foreach ( $d['summary']['open_by_severity'] as $s => $n ) {
			$parts[] = $s . ' ' . $n;
		}
		$L[] = '- Open on the site right now: ' . implode( ', ', $parts );
		if ( null !== $d['hardening']['score'] ) {
			$L[] = '- Hardening score: ' . $d['hardening']['score'] . '/100';
		}
		$L[] = '';
		$L[] = '## Findings';
		$L[] = '';
		if ( ! $d['findings'] ) {
			$L[] = 'No findings match the export scope.';
			$L[] = '';
		}
		$i = 0;
		foreach ( $d['findings'] as $f ) {
			$i++;
			$L[] = '### ' . $i . '. [' . strtoupper( $f['severity'] ) . '] ' . self::md( $f['title'] );
			$L[] = '';
			$L[] = '- Area: ' . $f['area'] . ' (' . $f['type'] . ')';
			if ( $f['component'] ) {
				$L[] = '- Component: ' . $f['component_name'] . ' [' . $f['component'] . ']';
			}
			if ( $f['file'] ) {
				$L[] = '- Location: `' . $f['file'] . ( $f['line'] ? ':' . $f['line'] : '' ) . '`';
			}
			$L[] = '- Status: ' . $f['status'] . '; seen ' . $f['hits'] . ' time(s), first ' . $f['first_seen'] . ', last ' . $f['last_seen'];
			if ( $f['explanation'] ) {
				$L[] = '- Explanation: ' . self::md( $f['explanation'] );
			}
			foreach ( $f['details'] as $k => $v ) {
				$L[] = '- ' . str_replace( '_', ' ', $k ) . ': ' . ( preg_match( '/[`<>{}$]/', $v ) ? '`' . str_replace( '`', "'", self::md( $v ) ) . '`' : self::md( $v ) );
			}
			$L[] = '';
		}

		if ( isset( $d['packages'] ) ) {
			$L[] = '## Installed plugins and themes';
			$L[] = '';
			$L[] = '| Type | Name | Slug | Version | Active | Author | Plugin URI | Update URI |';
			$L[] = '|---|---|---|---|---|---|---|---|';
			foreach ( $d['packages'] as $p ) {
				$L[] = '| ' . implode( ' | ', array_map( array( __CLASS__, 'md' ), array( $p['type'], $p['name'], $p['slug'], $p['version'], $p['active'] ? 'yes' : 'no', $p['author'], $p['plugin_uri'], $p['update_uri'] ) ) ) . ' |';
			}
			$L[] = '';
			$L[] = '## Outbound hosts (last 30 days)';
			$L[] = '';
			if ( $d['outbound_hosts'] ) {
				$L[] = '| Host | Requested by | Requests | Faked | Errors | First seen | Sample URL |';
				$L[] = '|---|---|---|---|---|---|---|';
				foreach ( $d['outbound_hosts'] as $h ) {
					$L[] = '| ' . implode( ' | ', array_map( array( __CLASS__, 'md' ), array( $h['host'], $h['requested_by'], $h['requests'], $h['faked'], $h['errors'], $h['first_seen'], $h['sample_url'] ) ) ) . ' |';
				}
			} else {
				$L[] = 'None recorded.';
			}
			$L[] = '';
			$L[] = '## Third-party callbacks on sensitive hooks';
			$L[] = '';
			if ( $d['sensitive_hooks'] ) {
				$L[] = '| Group | Hook | Component | Callback | Location | Priority |';
				$L[] = '|---|---|---|---|---|---|';
				foreach ( $d['sensitive_hooks'] as $h ) {
					$L[] = '| ' . implode( ' | ', array_map( array( __CLASS__, 'md' ), array( $h['group'], $h['hook'], $h['component'], $h['callback'], $h['location'], $h['priority'] ) ) ) . ' |';
				}
			} else {
				$L[] = 'Only WordPress core.';
			}
			$L[] = '';
			$L[] = '## Scheduled tasks not handled by WordPress core';
			$L[] = '';
			if ( $d['scheduled_tasks'] ) {
				$L[] = '| Hook | Recurrence | Next run | Handler | Random name | Suspicious arguments |';
				$L[] = '|---|---|---|---|---|---|';
				foreach ( $d['scheduled_tasks'] as $c ) {
					$L[] = '| ' . implode( ' | ', array_map( array( __CLASS__, 'md' ), array( $c['hook'], $c['recurrence'], $c['next_run'], $c['handler'], $c['random_name'] ? 'yes' : 'no', $c['suspicious_args'] ? $c['suspicious_args'] : '' ) ) ) . ' |';
				}
			} else {
				$L[] = 'None.';
			}
			$L[] = '';
		}

		$L[] = '## Hardening checks';
		$L[] = '';
		if ( $d['hardening']['checks'] ) {
			$L[] = 'Checked ' . $d['hardening']['checked'] . ', score ' . $d['hardening']['score'] . '/100.';
			$L[] = '';
			$L[] = '| Result | Check | Detail | Fix |';
			$L[] = '|---|---|---|---|';
			foreach ( $d['hardening']['checks'] as $c ) {
				$L[] = '| ' . implode( ' | ', array_map( array( __CLASS__, 'md' ), array( $c['status'] . ( $c['severity'] ? ' (' . $c['severity'] . ')' : '' ), $c['check'], (string) $c['detail'], (string) $c['fix'] ) ) ) . ' |';
			}
		} else {
			$L[] = 'Not checked yet.';
		}
		$L[] = '';
		$L[] = '## File integrity';
		$L[] = '';
		if ( $d['integrity']['last_scan'] ) {
			$L[] = 'Last scan ' . $d['integrity']['last_scan'] . ': ' . $d['integrity']['files_checked'] . ' files, ' . $d['integrity']['problems'] . ' problems.';
			$L[] = '';
			foreach ( $d['integrity']['packages'] as $pkg => $mode ) {
				$L[] = '- ' . $pkg . ': verified against ' . $mode;
			}
		} else {
			$L[] = 'No scan finished yet.';
		}
		$L[] = '';
		return implode( "\n", $L );
	}
}
