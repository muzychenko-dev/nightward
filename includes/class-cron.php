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
			add_action( 'shutdown', array( __CLASS__, 'mark_wpcron' ), 1 );
		} elseif ( ! ( defined( 'WP_CLI' ) && WP_CLI ) && ! ( defined( 'WP_INSTALLING' ) && WP_INSTALLING ) && Settings::get( 'cron_fallback', 1 ) ) {
			add_action( 'shutdown', array( __CLASS__, 'fallback' ), 99 );
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
		if ( isset( $_GET['doing_wp_cron'] ) && 'nightward-test' === $_GET['doing_wp_cron'] ) { // phpcs:ignore WordPress.Security.NonceVerification
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
		);
	}

	/** All WordPress events (not only ours) that should have run more than 10 minutes ago. */
	public static function overdue() {
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
	 * Ask wp-cron.php the way WordPress does, but wait for the answer. The lock key is
	 * deliberately wrong, so wp-cron.php loads and exits without running anything.
	 */
	public static function loopback_test() {
		$req = apply_filters(
			'cron_request',
			array(
				'url'  => add_query_arg( 'doing_wp_cron', 'nightward-test', site_url( 'wp-cron.php' ) ),
				'key'  => 'nightward-test',
				'args' => array(
					'timeout'   => 0.01,
					'blocking'  => false,
					'sslverify' => apply_filters( 'https_local_ssl_verify', false ),
				),
			),
			'nightward-test'
		);
		$url  = add_query_arg( 'doing_wp_cron', 'nightward-test', remove_query_arg( 'doing_wp_cron', $req['url'] ) );
		$args = array(
			'timeout'     => 15,
			'blocking'    => true,
			'redirection' => 0,
			'sslverify'   => isset( $req['args']['sslverify'] ) ? $req['args']['sslverify'] : false,
			'headers'     => array( 'X-Nightward-Probe' => 'cron' ),
		);
		$t0   = microtime( true );
		$resp = wp_remote_post( $url, $args );
		$ms   = (int) round( ( microtime( true ) - $t0 ) * 1000 );
		$host = (string) wp_parse_url( $url, PHP_URL_HOST );
		$r    = array(
			'url'     => $url,
			'ms'      => $ms,
			'code'    => 0,
			'error'   => '',
			'title'   => '',
			'via'     => '',
			'verdict' => 'ok',
			'checked' => time(),
		);
		if ( is_wp_error( $resp ) ) {
			$r['error']   = $resp->get_error_message();
			$r['verdict'] = 'unreachable';
		} else {
			$r['code'] = (int) wp_remote_retrieve_response_code( $resp );
			$body      = (string) wp_remote_retrieve_body( $resp );
			if ( preg_match( '~<title[^>]*>(.*?)</title>~is', $body, $m ) ) {
				$r['title'] = trim( wp_strip_all_tags( html_entity_decode( $m[1], ENT_QUOTES, 'UTF-8' ) ) );
			}
			$hdr = wp_remote_retrieve_headers( $resp );
			if ( wp_remote_retrieve_header( $resp, 'cf-ray' ) ) {
				$r['via'] = 'Cloudflare';
			} elseif ( wp_remote_retrieve_header( $resp, 'x-sucuri-id' ) ) {
				$r['via'] = 'Sucuri';
			} elseif ( $hdr && wp_remote_retrieve_header( $resp, 'server' ) ) {
				$r['via'] = substr( (string) wp_remote_retrieve_header( $resp, 'server' ), 0, 40 );
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
			} elseif ( $ms > 8000 ) {
				$r['verdict'] = 'slow';
			}
		}
		$r['host'] = $host;
		update_option( 'nightward_cron_test', $r, false );
		return $r;
	}

	/** Human explanation for a loopback verdict. */
	public static function verdict_text( array $r ) {
		switch ( $r['verdict'] ) {
			case 'unreachable':
				/* translators: 1: host, 2: error message */
				return sprintf( __( 'The server cannot connect to its own address %1$s (%2$s). WordPress starts WP-Cron with exactly this request, so tasks never run. Usually a firewall, DNS or hosting restriction: ask the host to allow requests from the server to its own domain, or set up a server cron job below.', 'nightward' ), $r['host'], $r['error'] );
			case 'redirect':
				/* translators: %s: redirect target */
				return sprintf( __( 'wp-cron.php answers with a redirect to %s. WordPress does not follow redirects when it starts WP-Cron, so tasks never run. Make the WordPress and site addresses in Settings → General match the real address (https, www) or remove the redirect for wp-cron.php.', 'nightward' ), isset( $r['location'] ) && $r['location'] ? $r['location'] : '?' );
			case 'auth':
				return __( 'wp-cron.php asks for a password (HTTP 401). Password protection of the site also blocks the request that starts WP-Cron. Exclude wp-cron.php from the protection or set up a server cron job below.', 'nightward' );
			case 'blocked':
				/* translators: 1: HTTP status, 2: CDN or firewall name */
				return sprintf( __( 'wp-cron.php is blocked with HTTP %1$d%2$s. A firewall, security plugin or maintenance mode rejects the request that starts WP-Cron. Allow wp-cron.php for requests from the server itself or set up a server cron job below.', 'nightward' ), $r['code'], $r['title'] ? ' ("' . $r['title'] . '")' : ( $r['via'] ? ' (' . $r['via'] . ')' : '' ) );
			case 'page':
				/* translators: %s: page title */
				return sprintf( __( 'wp-cron.php returns a web page ("%s") instead of an empty answer. A maintenance or coming-soon mode, a firewall or a cache intercepts it. Exclude wp-cron.php or set up a server cron job below.', 'nightward' ), $r['title'] ? $r['title'] : 'HTML' );
			case 'slow':
				/* translators: %s: seconds */
				return sprintf( __( 'wp-cron.php is reachable but the answer took %s s. WordPress waits about a second when it starts WP-Cron, so a slow start can be dropped. A server cron job is more reliable.', 'nightward' ), number_format_i18n( $r['ms'] / 1000, 1 ) );
		}
		/* translators: %s: milliseconds */
		return sprintf( __( 'wp-cron.php is reachable from the server (%s ms), so WordPress can start WP-Cron.', 'nightward' ), number_format_i18n( $r['ms'] ) );
	}

	/** Most likely reason why tasks wait, from what can be seen without a request. */
	public static function diagnosis( array $h, $test = null ) {
		$out = array();
		if ( $h['disabled'] ) {
			$out[] = __( 'DISABLE_WP_CRON is set in wp-config.php, so WordPress does not start WP-Cron by itself. That is correct only if a server cron job requests wp-cron.php; here no such job seems to run.', 'nightward' );
		}
		if ( $test && 'ok' !== $test['verdict'] ) {
			$out[] = self::verdict_text( $test );
		}
		if ( ! $out && $test ) {
			$out[] = self::verdict_text( $test ) . ' ' . __( 'WP-Cron starts only when someone opens the site or the dashboard, so on a site with few visits tasks wait. A server cron job removes the dependence on visits.', 'nightward' );
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
