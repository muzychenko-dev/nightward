<?php
/**
 * Scheduling. The daily report is a single event re-created after each run at
 * the exact local time — a plain "daily" recurrence drifts and ignores DST.
 */

namespace Nightward;

defined( 'ABSPATH' ) || exit;

class Cron {

	public static function init() {
		add_action( 'nightward_daily_report', array( __CLASS__, 'run_daily_report' ) );
		add_action( 'nightward_hourly', array( __CLASS__, 'run_hourly' ) );
		add_action( 'nightward_daily_maintenance', array( __CLASS__, 'run_daily_maintenance' ) );
		add_action( 'nightward_integrity_start', array( 'Nightward\\Scanner\\Integrity', 'start' ) );
		add_action( 'nightward_integrity_step', array( 'Nightward\\Scanner\\Integrity', 'step' ) );
		add_action( 'nightward_instant_retry', array( 'Nightward\\Reports', 'send_pending_instant' ) );
		add_action( 'update_option_' . Settings::OPTION, array( __CLASS__, 'schedule_all' ) );
		if ( wp_doing_cron() ) {
			self::note_arrival();
			add_action( 'shutdown', array( __CLASS__, 'mark_wpcron' ), 1 );
			return;
		}
		add_filter( 'cron_request', array( __CLASS__, 'note_spawn' ), PHP_INT_MAX );
		if ( ! ( defined( 'WP_CLI' ) && WP_CLI ) && ! ( defined( 'WP_INSTALLING' ) && WP_INSTALLING ) && Settings::get( 'cron_fallback', 1 ) ) {
			add_action( 'shutdown', array( __CLASS__, 'fallback' ), 99 );
		}
	}

	/** WordPress is about to start WP-Cron with a background request. */
	public static function note_spawn( $req ) {
		$sp   = get_option( 'nightward_cron_spawn' );
		$sp   = is_array( $sp ) ? $sp : array( 'last' => 0, 'first' => 0 );
		$seen = get_option( 'nightward_cron_seen' );
		if ( $sp['last'] < time() - 60 ) {
			// "first" = first start attempt since a request last reached wp-cron.php.
			if ( ! $sp['first'] || ( is_array( $seen ) && $seen['at'] >= $sp['first'] ) ) {
				$sp['first'] = time();
			}
			$sp['last'] = time();
			update_option( 'nightward_cron_spawn', $sp, false );
		}
		return $req;
	}

	/**
	 * A request reached wp-cron.php and WordPress loaded. Records whether its key matches
	 * the lock WordPress stored: a mismatch means transients do not survive between requests.
	 */
	private static function note_arrival() {
		$check = ! empty( $_GET['nightward_check'] ); // phpcs:ignore WordPress.Security.NonceVerification
		if ( empty( $_GET['doing_wp_cron'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			$lock = 'external';
		} else {
			$key  = (string) wp_unslash( $_GET['doing_wp_cron'] ); // phpcs:ignore
			$t    = get_transient( 'doing_cron' );
			$lock = ( false === $t || '' === $t ) ? 'empty' : ( (string) $t === $key ? 'match' : 'mismatch' );
		}
		if ( ! headers_sent() ) {
			header( 'X-Nightward-Cron: ' . $lock );
		}
		if ( $check ) {
			// Nightward's own check is kept apart, so it does not hide what real starts do.
			update_option( 'nightward_cron_check_seen', array( 'at' => time(), 'lock' => $lock ), false );
			return;
		}
		$prev = get_option( 'nightward_cron_seen' );
		if ( ! is_array( $prev ) || $prev['at'] < time() - 30 || $prev['lock'] !== $lock ) {
			update_option( 'nightward_cron_seen', array( 'at' => time(), 'lock' => $lock ), false );
		}
	}

	/** WP-Cron really fired in this request. */
	public static function mark_wpcron() {
		// Count only runs that passed wp-cron.php's lock check and reached the events loop:
		// not Nightward's own connection check, not a request stopped by a firewall plugin.
		if ( ! did_action( 'wp_loaded' ) ) {
			return;
		}
		if ( isset( $GLOBALS['doing_wp_cron'] ) && array_key_exists( 'doing_cron_transient', $GLOBALS ) && $GLOBALS['doing_cron_transient'] !== $GLOBALS['doing_wp_cron'] ) {
			return;
		}
		if ( ! empty( $_GET['nightward_check'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			update_option( 'nightward_cron_check_done', time(), false );
			return;
		}
		if ( (int) get_option( 'nightward_last_wpcron', 0 ) < time() - 60 ) {
			update_option( 'nightward_last_wpcron', time(), false );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Backup scheduler: Nightward's own tasks run from ordinary requests   */
	/* when WP-Cron does not fire.                                          */
	/* ------------------------------------------------------------------ */

	const OWN_HOOKS = array( 'nightward_daily_report', 'nightward_hourly', 'nightward_daily_maintenance', 'nightward_integrity_start', 'nightward_integrity_step', 'nightward_instant_retry' );
	const HEAVY     = array( 'nightward_daily_maintenance', 'nightward_integrity_start', 'nightward_integrity_step' );
	const GRACE     = 900; // WP-Cron gets 15 minutes before Nightward steps in

	/** Nightward events that are due for longer than $grace seconds. */
	public static function own_overdue( $grace = self::GRACE ) {
		$out  = array();
		$cron = function_exists( '_get_cron_array' ) ? _get_cron_array() : array();
		$lim  = time() - $grace;
		foreach ( (array) $cron as $ts => $hooks ) {
			if ( $ts > $lim ) {
				break; // the array is sorted by time
			}
			foreach ( (array) $hooks as $hook => $events ) {
				if ( in_array( $hook, self::OWN_HOOKS, true ) ) {
					foreach ( (array) $events as $ev ) {
						$out[] = array( 'ts' => (int) $ts, 'hook' => $hook, 'schedule' => isset( $ev['schedule'] ) ? $ev['schedule'] : false, 'args' => isset( $ev['args'] ) ? (array) $ev['args'] : array() );
					}
				}
			}
		}
		return $out;
	}

	public static function fallback() {
		$due = self::own_overdue();
		if ( ! $due ) {
			return;
		}
		$finished = false;
		if ( function_exists( 'fastcgi_finish_request' ) ) {
			$finished = fastcgi_finish_request();
		} elseif ( function_exists( 'litespeed_finish_request' ) ) {
			$finished = litespeed_finish_request();
		}
		// Without a way to finish the response first, heavy scans wait for an AJAX request
		// (Heartbeat in the dashboard) so that a page view is never slowed down by them.
		$heavy_ok = $finished || wp_doing_ajax();
		self::run_due( $due, $heavy_ok, 'fallback' );
	}

	/**
	 * Run due Nightward events the way wp-cron.php does: reschedule or unschedule first,
	 * then fire the hook.
	 *
	 * @return int number of events run
	 */
	public static function run_due( array $due, $heavy_ok = true, $how = 'fallback' ) {
		if ( ! add_option( 'nightward_fallback_lock', time(), '', false ) ) {
			$lock = (int) get_option( 'nightward_fallback_lock', 0 );
			if ( $lock > time() - 5 * MINUTE_IN_SECONDS ) {
				return 0;
			}
			update_option( 'nightward_fallback_lock', time(), false );
		}
		ignore_user_abort( true );
		$n     = 0;
		$start = microtime( true );
		foreach ( $due as $ev ) {
			if ( ! $heavy_ok && in_array( $ev['hook'], self::HEAVY, true ) ) {
				continue;
			}
			if ( $n && microtime( true ) - $start > 20 ) {
				break; // the rest on the next request
			}
			if ( $ev['schedule'] ) {
				wp_reschedule_event( $ev['ts'], $ev['schedule'], $ev['hook'], $ev['args'] );
			}
			wp_unschedule_event( $ev['ts'], $ev['hook'], $ev['args'] );
			do_action_ref_array( $ev['hook'], $ev['args'] );
			$n++;
		}
		delete_option( 'nightward_fallback_lock' );
		if ( $n && doing_action( 'shutdown' ) && Settings::enabled( 'outbound' ) ) {
			Monitor\Outbound::flush(); // its own shutdown pass has already run
		}
		if ( $n ) {
			$st          = (array) get_option( 'nightward_fallback', array() );
			$st['last']  = time();
			$st['how']   = $how;
			$st['count'] = ( isset( $st['count'] ) ? (int) $st['count'] : 0 ) + $n;
			update_option( 'nightward_fallback', $st, false );
		}
		return $n;
	}

	/** Next GMT timestamp of HH:MM in the site timezone. */
	public static function next_local( $hhmm ) {
		list( $h, $m ) = array_map( 'intval', explode( ':', $hhmm ) + array( 0, 0 ) );
		$tz  = wp_timezone();
		$now = new \DateTimeImmutable( 'now', $tz );
		$at  = $now->setTime( $h, $m, 0 );
		if ( $at <= $now ) {
			$at = $at->modify( '+1 day' );
		}
		return $at->getTimestamp();
	}

	public static function schedule_all() {
		wp_clear_scheduled_hook( 'nightward_daily_report' );
		if ( Settings::get( 'report_enabled', 1 ) ) {
			wp_schedule_single_event( self::next_local( Settings::get( 'report_time', '20:00' ) ), 'nightward_daily_report' );
		}
		wp_clear_scheduled_hook( 'nightward_daily_maintenance' );
		wp_schedule_single_event( self::next_local( Settings::get( 'integrity_time', '03:30' ) ), 'nightward_daily_maintenance' );
		if ( ! wp_next_scheduled( 'nightward_hourly' ) ) {
			wp_schedule_event( time() + 300, 'hourly', 'nightward_hourly' );
		}
	}

	public static function unschedule_all() {
		foreach ( array( 'nightward_daily_report', 'nightward_hourly', 'nightward_daily_maintenance', 'nightward_integrity_start', 'nightward_integrity_step', 'nightward_instant_retry' ) as $h ) {
			wp_clear_scheduled_hook( $h );
		}
	}

	public static function run_daily_report() {
		update_option( 'nightward_last_report_run', time(), false );
		Reports::send_digest();
		if ( Settings::get( 'report_enabled', 1 ) ) {
			wp_schedule_single_event( self::next_local( Settings::get( 'report_time', '20:00' ) ), 'nightward_daily_report' );
		}
	}

	public static function run_hourly() {
		update_option( 'nightward_last_hourly', time(), false );
		if ( Settings::enabled( 'cron' ) ) {
			Monitor\Cron_Guard::check();
		}
		if ( Settings::enabled( 'uploads' ) ) {
			Scanner\Upload_Guard::scan( true );
		}
		if ( Settings::enabled( 'update_channel' ) ) {
			Scanner\Update_Channel::check_offered_updates();
		}
		if ( Settings::enabled( 'privilege' ) ) {
			Monitor\Privilege_Guard::audit_admins();
		}
		if ( Settings::enabled( 'options' ) ) {
			Monitor\Options_Watch::evaluate();
		}
		// Самоперевірка: якщо звіт мав піти >2 год тому, а не пішов — WP-Cron не працює.
		$next = wp_next_scheduled( 'nightward_daily_report' );
		if ( Settings::get( 'report_enabled', 1 ) && ( ! $next || $next < time() - 2 * HOUR_IN_SECONDS ) ) {
			self::schedule_all();
		}
	}

	public static function run_daily_maintenance() {
		Events::purge( Settings::get( 'retention_days', 60 ) );
		if ( Settings::enabled( 'integrity' ) ) {
			Scanner\Integrity::start();
		}
		if ( Settings::enabled( 'uploads' ) ) {
			Scanner\Upload_Guard::scan( false );
		}
		if ( Settings::enabled( 'hardening' ) ) {
			Scanner\Hardening::run();
		}
		if ( Settings::enabled( 'options' ) ) {
			Monitor\Options_Watch::autoload_check();
		}
		wp_schedule_single_event( self::next_local( Settings::get( 'integrity_time', '03:30' ) ), 'nightward_daily_maintenance' );
	}

	/** Is WP-Cron actually firing? Used on the dashboard, in reports and in hardening. */
	public static function health() {
		$last     = (int) get_option( 'nightward_last_hourly', 0 );
		$overdue  = self::overdue();
		$fb       = (array) get_option( 'nightward_fallback', array() );
		$disabled = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;
		return array(
			'disabled'      => $disabled,
			'alternate'     => defined( 'ALTERNATE_WP_CRON' ) && ALTERNATE_WP_CRON,
			'last_hourly'   => $last,
			'last_wpcron'   => (int) get_option( 'nightward_last_wpcron', 0 ),
			// Tasks waiting for more than an hour mean that nobody runs WP-Cron.
			'stale'         => $overdue['oldest'] && ( time() - $overdue['oldest'] ) > HOUR_IN_SECONDS,
			'overdue'       => $overdue,
			'next_report'   => wp_next_scheduled( 'nightward_daily_report' ),
			'last_report'   => (int) get_option( 'nightward_last_report_sent', 0 ),
			'fallback'      => (bool) Settings::get( 'cron_fallback', 1 ),
			'fallback_last' => isset( $fb['last'] ) ? (int) $fb['last'] : 0,
			'hooked'        => false !== has_action( 'init', 'wp_cron' ),
			'spawn'         => is_array( get_option( 'nightward_cron_spawn' ) ) ? get_option( 'nightward_cron_spawn' ) : null,
			'seen'          => is_array( get_option( 'nightward_cron_seen' ) ) ? get_option( 'nightward_cron_seen' ) : null,
			'prepend'       => (string) ini_get( 'auto_prepend_file' ),
		);
	}

	/** Read an option written by another request, past the in-memory caches. */
	private static function fresh_option( $name ) {
		wp_cache_delete( $name, 'options' );
		wp_cache_delete( 'notoptions', 'options' );
		wp_cache_delete( 'alloptions', 'options' );
		return get_option( $name );
	}

	/** Poll $probe until it returns non-null or $seconds pass. */
	private static function wait_for( $probe, $seconds ) {
		$until = microtime( true ) + $seconds;
		do {
			$v = $probe();
			if ( null !== $v ) {
				return $v;
			}
			usleep( 400000 );
		} while ( microtime( true ) < $until );
		return null;
	}

	/** All WordPress events (not only ours) that should have run more than 10 minutes ago. */
	public static function overdue( $fresh = false ) {
		if ( $fresh ) {
			self::fresh_option( 'cron' );
		}
		$cron  = function_exists( '_get_cron_array' ) ? _get_cron_array() : array();
		$lim   = time() - 10 * MINUTE_IN_SECONDS;
		$count = 0;
		$hooks = array();
		$old   = 0;
		foreach ( (array) $cron as $ts => $hs ) {
			if ( $ts > $lim ) {
				break;
			}
			if ( ! $old ) {
				$old = (int) $ts;
			}
			foreach ( (array) $hs as $hook => $events ) {
				$count += count( (array) $events );
				$hooks[ $hook ] = true;
			}
		}
		return array( 'count' => $count, 'oldest' => $old, 'hooks' => array_slice( array_keys( $hooks ), 0, 12 ) );
	}

	/**
	 * Start WP-Cron the way WordPress does (same lock, same URL filters), but wait for
	 * the answer. Due tasks really run. Tells apart: no connection, redirect, password,
	 * firewall page, an answer without WordPress behind it, a lock that does not survive
	 * between requests, and a working WP-Cron.
	 */
	public static function loopback_test() {
		$before = self::overdue();
		$key    = sprintf( '%.22F', microtime( true ) );
		set_transient( 'doing_cron', $key );
		remove_filter( 'cron_request', array( __CLASS__, 'note_spawn' ), PHP_INT_MAX );
		$req = apply_filters(
			'cron_request',
			array(
				'url'  => add_query_arg( 'doing_wp_cron', $key, site_url( 'wp-cron.php' ) ),
				'key'  => $key,
				'args' => array(
					'timeout'   => 0.01,
					'blocking'  => false,
					'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
				),
			),
			$key
		);
		add_filter( 'cron_request', array( __CLASS__, 'note_spawn' ), PHP_INT_MAX );
		$url  = add_query_arg( 'nightward_check', '1', $req['url'] );
		$args = array(
			'timeout'     => 45,
			'blocking'    => true,
			'redirection' => 0,
			'sslverify'   => isset( $req['args']['sslverify'] ) ? $req['args']['sslverify'] : false,
			'headers'     => array( 'X-Nightward-Probe' => 'cron' ),
		);
		$t0   = microtime( true );
		$resp = wp_remote_post( $url, $args );
		$ms   = (int) round( ( microtime( true ) - $t0 ) * 1000 );

		$t0i = (int) floor( $t0 );
		$r   = array(
			'url'     => remove_query_arg( array( 'doing_wp_cron', 'nightward_check' ), $url ),
			'host'    => (string) wp_parse_url( $url, PHP_URL_HOST ),
			'ms'      => $ms,
			'run_ms'  => 0,
			'code'    => 0,
			'error'   => '',
			'title'   => '',
			'via'     => '',
			'ran'     => 0,
			'prepend' => (string) ini_get( 'auto_prepend_file' ),
			'verdict' => 'ok',
			'checked' => time(),
		);
		if ( is_wp_error( $resp ) ) {
			$r['error'] = $resp->get_error_message();
			$seen       = self::fresh_option( 'nightward_cron_check_seen' );
			if ( ! ( is_array( $seen ) && $seen['at'] >= $t0i ) ) {
				$r['verdict'] = 'unreachable';
			}
		} else {
			$r['code'] = (int) wp_remote_retrieve_response_code( $resp );
			$body      = (string) wp_remote_retrieve_body( $resp );
			if ( preg_match( '~<title[^>]*>(.*?)</title>~is', $body, $m ) ) {
				$r['title'] = trim( wp_strip_all_tags( html_entity_decode( $m[1], ENT_QUOTES, 'UTF-8' ) ) );
			}
			if ( wp_remote_retrieve_header( $resp, 'cf-ray' ) ) {
				$r['via'] = 'Cloudflare';
			} elseif ( wp_remote_retrieve_header( $resp, 'x-sucuri-id' ) ) {
				$r['via'] = 'Sucuri';
			}
			if ( $r['code'] >= 300 && $r['code'] < 400 ) {
				$r['verdict']  = 'redirect';
				$r['location'] = (string) wp_remote_retrieve_header( $resp, 'location' );
			} elseif ( 401 === $r['code'] ) {
				$r['verdict'] = 'auth';
			} elseif ( $r['code'] >= 400 ) {
				$r['verdict'] = 'blocked';
			} elseif ( '' !== trim( $body ) && false !== stripos( $body, '<html' ) ) {
				$r['verdict'] = 'page';
			}
		}

		// On PHP-FPM and LiteSpeed wp-cron.php sends its empty answer before it even loads
		// WordPress, so the answer proves little. Wait for WordPress to report from inside.
		if ( 'ok' === $r['verdict'] ) {
			if ( function_exists( 'set_time_limit' ) ) {
				@set_time_limit( 90 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			}
			$seen = self::wait_for( function () use ( $t0i ) {
				$v = self::fresh_option( 'nightward_cron_check_seen' );
				return is_array( $v ) && $v['at'] >= $t0i ? $v : null;
			}, 10 );
			if ( ! $seen ) {
				$r['verdict'] = 'no_wp';
			} elseif ( 'match' !== $seen['lock'] ) {
				$r['verdict'] = 'lock';
			} else {
				$done = self::wait_for( function () use ( $t0i ) {
					return (int) self::fresh_option( 'nightward_cron_check_done' ) >= $t0i ? true : null;
				}, 25 );
				$r['run_ms'] = (int) round( ( microtime( true ) - $t0 ) * 1000 );
				$r['ran']    = max( 0, $before['count'] - self::overdue( true )['count'] );
				if ( ! $done ) {
					$r['verdict'] = 'slow';
				}
			}
		}
		if ( 'ok' !== $r['verdict'] && 'slow' !== $r['verdict'] ) {
			delete_transient( 'doing_cron' ); // do not leave our lock behind
		}
		update_option( 'nightward_cron_test', $r, false );
		return $r;
	}

	/** Human explanation for a check result. */
	public static function verdict_text( array $r ) {
		switch ( $r['verdict'] ) {
			case 'unreachable':
				/* translators: 1: host, 2: error message */
				return sprintf( __( 'The server cannot connect to its own address %1$s (%2$s). WordPress starts WP-Cron with exactly this request, so tasks never run. Usually a firewall, DNS or hosting restriction: ask the host to allow requests from the server to its own domain, or set up a server cron job below.', 'nightward' ), $r['host'], $r['error'] );
			case 'redirect':
				/* translators: %s: redirect target */
				return sprintf( __( 'wp-cron.php answers with a redirect to %s. WordPress does not follow redirects when it starts WP-Cron, so tasks never run. Make the WordPress and site addresses in Settings → General match the real address (https, www) or remove the redirect for wp-cron.php.', 'nightward' ), ! empty( $r['location'] ) ? $r['location'] : '?' );
			case 'auth':
				return __( 'wp-cron.php asks for a password (HTTP 401). Password protection of the site also blocks the request that starts WP-Cron. Exclude wp-cron.php from the protection or set up a server cron job below.', 'nightward' );
			case 'blocked':
				/* translators: 1: HTTP status, 2: page title or CDN name */
				return sprintf( __( 'wp-cron.php is blocked with HTTP %1$d%2$s. A firewall, security plugin or maintenance mode rejects the request that starts WP-Cron. Allow wp-cron.php for requests from the server itself or set up a server cron job below.', 'nightward' ), $r['code'], $r['title'] ? ' ("' . $r['title'] . '")' : ( $r['via'] ? ' (' . $r['via'] . ')' : '' ) );
			case 'page':
				/* translators: %s: page title */
				return sprintf( __( 'wp-cron.php returns a web page ("%s") instead of an empty answer. A maintenance or coming-soon mode, a firewall or a cache intercepts it. Exclude wp-cron.php or set up a server cron job below.', 'nightward' ), $r['title'] ? $r['title'] : 'HTML' );
			case 'no_wp':
				$t = __( 'wp-cron.php answers, but WordPress never started behind it: Nightward, which loads with WordPress, did not see the request within 10 seconds. Something stops it before WordPress: a firewall that runs first, a server rule or a cache.', 'nightward' );
				if ( $r['prepend'] ) {
					/* translators: %s: file path */
					$t .= ' ' . sprintf( __( 'PHP runs %s before every request (auto_prepend_file); that is usually a security plugin\'s firewall, check its settings for wp-cron.php or for blocked requests from the server\'s own IP address.', 'nightward' ), $r['prepend'] );
				}
				return $t . ' ' . __( 'A server cron job that runs WP-CLI bypasses all of this.', 'nightward' );
			case 'lock':
				return __( 'The request reached WordPress, but the lock WordPress had just saved was not there (transients do not survive between requests), so wp-cron.php exits without running anything. Usually a broken object cache: check the object-cache.php drop-in and the Redis or Memcached connection.', 'nightward' );
			case 'slow':
				/* translators: %s: seconds */
				return sprintf( __( 'WP-Cron started and is running the waiting tasks; they were not finished when the check stopped waiting after %s s. WP-Cron itself works.', 'nightward' ), number_format_i18n( $r['run_ms'] / 1000, 0 ) );
		}
		/* translators: 1: number of tasks, 2: seconds */
		return sprintf( _n( 'WP-Cron works when it is started: WordPress picked up the request and finished %1$d waiting task in %2$s s.', 'WP-Cron works when it is started: WordPress picked up the request and finished %1$d waiting tasks in %2$s s.', $r['ran'], 'nightward' ), $r['ran'], number_format_i18n( max( 1, $r['run_ms'] ) / 1000, 1 ) );
	}

	/** Most likely reason why tasks wait. */
	public static function diagnosis( array $h, $test = null ) {
		$out = array();
		if ( $test && ! in_array( $test['verdict'], array( 'ok', 'slow' ), true ) ) {
			$out[] = self::verdict_text( $test );
			return $out;
		}
		if ( $test ) {
			$out[] = self::verdict_text( $test );
		}
		if ( $h['disabled'] ) {
			$out[] = __( 'DISABLE_WP_CRON is set in wp-config.php, so WordPress does not start WP-Cron by itself. That is correct only if a server cron job requests wp-cron.php; here no such job seems to run.', 'nightward' );
		} elseif ( ! $h['hooked'] ) {
			$out[] = __( 'WordPress\'s own WP-Cron start (wp_cron on init) has been removed by a plugin or theme, so page views never start it.', 'nightward' );
		} elseif ( $h['spawn'] && $h['spawn']['first'] && $h['spawn']['first'] < time() - 120 && $h['spawn']['last'] > time() - 2 * HOUR_IN_SECONDS && ( ! $h['seen'] || $h['seen']['at'] < $h['spawn']['first'] ) ) {
			/* translators: %s: time */
			$out[] = sprintf( __( 'WordPress has been trying to start WP-Cron for %s, but none of these requests reached WordPress. WordPress sends them in the background and does not wait for the answer; behind a proxy, CDN or a slow TLS handshake such a short request is dropped. A server cron job solves it.', 'nightward' ), human_time_diff( $h['spawn']['first'] ) );
		} elseif ( $h['seen'] && 'mismatch' === $h['seen']['lock'] || $h['seen'] && 'empty' === $h['seen']['lock'] && $h['stale'] ) {
			$out[] = self::verdict_text( array( 'verdict' => 'lock' ) );
		} elseif ( $h['stale'] && ! $test ) {
			$out[] = __( 'Run the check: it starts WP-Cron the way WordPress does and shows where it stops.', 'nightward' );
		} elseif ( $h['stale'] ) {
			$out[] = __( 'WP-Cron starts only when someone opens the site or the dashboard, so on a site with few visits tasks wait. A server cron job removes the dependence on visits.', 'nightward' );
		}
		return $out;
	}

	/** Lines to give the host or put into the control panel. */
	public static function server_commands() {
		$url = site_url( 'wp-cron.php?doing_wp_cron' );
		return array(
			'curl' => '*/5 * * * * curl -fsS -o /dev/null "' . $url . '"',
			'wget' => '*/5 * * * * wget -q -O /dev/null "' . $url . '"',
			'cli'  => '*/5 * * * * cd ' . untrailingslashit( ABSPATH ) . ' && wp cron event run --due-now --quiet',
		);
	}
}
