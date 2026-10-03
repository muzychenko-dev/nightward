<?php
/**
 * Dashboard screens.
 */

namespace Nightward\Admin;

use Nightward\Attribution;
use Nightward\Cron;
use Nightward\DB;
use Nightward\Events;
use Nightward\Export;
use Nightward\Installer;
use Nightward\Plugin;
use Nightward\Reports;
use Nightward\Settings;
use Nightward\Util;
use Nightward\Monitor\Cron_Guard;
use Nightward\Monitor\Hooks_Watch;
use Nightward\Monitor\Outbound;
use Nightward\Monitor\Privilege_Guard;
use Nightward\Scanner\Hardening;
use Nightward\Scanner\Integrity;

defined( 'ABSPATH' ) || exit;

class Admin {

	const SLUG = 'nightward';
	const CAP  = 'manage_options';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'admin_post_nightward_save', array( __CLASS__, 'save_settings' ) );
		add_action( 'admin_post_nightward_preview', array( __CLASS__, 'preview_report' ) );
		add_action( 'admin_post_nightward_export', array( __CLASS__, 'download_export' ) );
		foreach ( array( 'status', 'integrity', 'hardening', 'test_email', 'trust_host', 'accept', 'export_text', 'cron_test', 'cron_run' ) as $a ) {
			add_action( 'wp_ajax_nightward_' . $a, array( __CLASS__, 'ajax_' . $a ) );
		}
		add_filter( 'plugin_action_links_' . plugin_basename( NIGHTWARD_FILE ), array( __CLASS__, 'action_links' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notices' ) );
	}

	private static function icon() {
		$svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path fill="black" fill-rule="evenodd" d="M10 1 2.5 4v5.2c0 4.6 3.1 8.3 7.5 9.8 4.4-1.5 7.5-5.2 7.5-9.8V4L10 1Zm1.4 4.1a4.9 4.9 0 1 0 3.9 8A4.1 4.1 0 0 1 11.4 5.1Z"/></svg>';
		return 'data:image/svg+xml;base64,' . base64_encode( $svg ); // phpcs:ignore
	}

	public static function menu() {
		$c     = Events::open_counts();
		$n     = $c['critical'] + $c['high'];
		$badge = $n ? ' <span class="awaiting-mod count-' . $n . '"><span class="pending-count">' . number_format_i18n( $n ) . '</span></span>' : '';
		add_menu_page( 'Nightward', 'Nightward' . $badge, self::CAP, self::SLUG, array( __CLASS__, 'render' ), self::icon(), 81 );
	}

	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( self::url( 'settings' ) ) . '">' . esc_html__( 'Settings', 'nightward' ) . '</a>' );
		return $links;
	}

	public static function url( $tab = 'overview', array $args = array() ) {
		return add_query_arg( array_merge( array( 'page' => self::SLUG, 'tab' => $tab ), $args ), admin_url( 'admin.php' ) );
	}

	public static function assets( $hook ) {
		if ( 'toplevel_page_' . self::SLUG !== $hook ) {
			return;
		}
		wp_enqueue_style( 'nightward', Plugin::url( 'assets/admin.css' ), array(), NIGHTWARD_VERSION );
		wp_enqueue_script( 'nightward', Plugin::url( 'assets/admin.js' ), array(), NIGHTWARD_VERSION, true );
		wp_localize_script( 'nightward', 'NIGHTWARD', array(
			'ajax'  => admin_url( 'admin-ajax.php' ),
			'nonce' => wp_create_nonce( 'nightward' ),
			'i18n'  => array(
				'copied'     => __( 'Copied. Paste it into ChatGPT, Claude, Gemini or another assistant.', 'nightward' ),
				'copyFailed' => __( 'The browser blocked copying. The text is selected below: press Ctrl+C.', 'nightward' ),
				'preparing'  => __( 'Preparing…', 'nightward' ),
				'checking'   => __( 'Checking…', 'nightward' ),
				'scanning'   => __( 'Scanning…', 'nightward' ),
				'scanDone'   => __( 'Scan finished.', 'nightward' ),
				/* translators: 1: done, 2: total, 3: files */
				'progress'   => __( '%1$s of %2$s packages · %3$s files', 'nightward' ),
				'running'    => __( 'Running checks…', 'nightward' ),
				'sending'    => __( 'Sending…', 'nightward' ),
				'sent'       => __( 'Sent. Check the inbox (and spam folder).', 'nightward' ),
				'failed'     => __( 'Failed', 'nightward' ),
				'confirmAccept' => __( 'Accept the current files of this package as the new reference? Do this only after you verified the changes.', 'nightward' ),
				'trusted'    => __( 'Trusted', 'nightward' ),
				'show'       => __( 'Details', 'nightward' ),
				'hide'       => __( 'Hide', 'nightward' ),
			),
		) );
	}

	public static function notices() {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$screen = get_current_screen();
		if ( ! $screen || 'toplevel_page_' . self::SLUG !== $screen->id ) {
			return;
		}
		$tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'overview'; // phpcs:ignore WordPress.Security.NonceVerification
		if ( in_array( $tab, array( 'overview', 'settings' ), true ) ) {
			return; // these screens show the full panel
		}
		$h = Cron::health();
		if ( $h['stale'] ) {
			echo '<div class="notice notice-warning"><p><strong>Nightward:</strong> ' . esc_html__( 'WP-Cron is not running, so scheduled tasks wait.', 'nightward' ) . ' <a href="' . esc_url( self::url( 'overview' ) . '#nw-cron' ) . '">' . esc_html__( 'Find out why and fix it', 'nightward' ) . '</a></p></div>';
		}
	}

	/**
	 * WP-Cron status, diagnosis and fixes. Shown on the overview when tasks wait,
	 * and always on the settings screen.
	 */
	private static function cron_panel( $always = false ) {
		$h = Cron::health();
		if ( ! $always && ! $h['stale'] ) {
			return;
		}
		$test = get_option( 'nightward_cron_test' );
		$test = is_array( $test ) && isset( $test['checked'], $test['run_ms'] ) && $test['checked'] > time() - DAY_IN_SECONDS ? wp_parse_args( $test, array( 'ms' => 0, 'run_ms' => 0, 'ran' => 0, 'code' => 0, 'error' => '', 'title' => '', 'via' => '', 'host' => '', 'prepend' => '' ) ) : null;
		$own  = Cron::own_overdue( 0 );
		$cls  = $h['stale'] ? ' nw-cron-bad' : '';
		echo '<section class="nw-card nw-cron' . esc_attr( $cls ) . '" id="nw-cron">';
		echo '<h2>' . ( $h['stale'] ? esc_html__( 'WP-Cron is not running', 'nightward' ) : esc_html__( 'Scheduled tasks (WP-Cron)', 'nightward' ) ) . '</h2>';
		if ( $h['stale'] ) {
			/* translators: 1: number of tasks, 2: time */
			echo '<p class="nw-lead">' . esc_html( sprintf( _n( '%1$d scheduled task has been waiting for %2$s. The daily report, scans and WordPress\'s own updates run only when WP-Cron fires.', '%1$d scheduled tasks have been waiting for %2$s. The daily report, scans and WordPress\'s own updates run only when WP-Cron fires.', $h['overdue']['count'], 'nightward' ), $h['overdue']['count'], human_time_diff( $h['overdue']['oldest'] ) ) ) . '</p>';
		}
		echo '<dl class="nw-dl">';
		echo '<dt>' . esc_html__( 'Status', 'nightward' ) . '</dt><dd>' . ( $h['stale'] ? '<b class="nw-bad">' . esc_html__( 'not running', 'nightward' ) . '</b>' : esc_html__( 'running', 'nightward' ) ) . '</dd>';
		echo '<dt>' . esc_html__( 'Last WP-Cron run', 'nightward' ) . '</dt><dd>' . ( $h['last_wpcron'] ? esc_html( sprintf( /* translators: %s: time */ __( '%s ago', 'nightward' ), human_time_diff( $h['last_wpcron'] ) ) ) : esc_html__( 'not seen since this version was installed', 'nightward' ) ) . '</dd>';
		if ( $h['overdue']['count'] ) {
			echo '<dt>' . esc_html__( 'Waiting tasks', 'nightward' ) . '</dt><dd><code>' . implode( '</code> <code>', array_map( 'esc_html', $h['overdue']['hooks'] ) ) . '</code></dd>';
		}
		echo '<dt>' . esc_html__( 'Start attempts by WordPress', 'nightward' ) . '</dt><dd>' . ( $h['spawn'] ? esc_html( sprintf( /* translators: %s: time */ __( 'last %s ago', 'nightward' ), human_time_diff( $h['spawn']['last'] ) ) ) : esc_html__( 'none recorded yet', 'nightward' ) ) . '</dd>';
		echo '<dt>' . esc_html__( 'Requests reaching wp-cron.php', 'nightward' ) . '</dt><dd>';
		if ( $h['seen'] ) {
			$locks = array(
				'match'    => __( 'lock matched', 'nightward' ),
				'mismatch' => __( 'lock did not match', 'nightward' ),
				'newer'    => __( 'lock already replaced by a newer one', 'nightward' ),
				'older'    => __( 'lock did not match', 'nightward' ),
				'empty'    => __( 'lock missing', 'nightward' ),
				'external' => __( 'from a server cron job', 'nightward' ),
			);
			/* translators: 1: time, 2: lock state */
			echo esc_html( sprintf( __( 'last %1$s ago, %2$s', 'nightward' ), human_time_diff( $h['seen']['at'] ), isset( $locks[ $h['seen']['lock'] ] ) ? $locks[ $h['seen']['lock'] ] : $h['seen']['lock'] ) );
		} else {
			echo esc_html__( 'none recorded yet', 'nightward' );
		}
		echo '</dd>';
		$ls = Cron::lock_summary();
		if ( $ls['log'] ) {
			echo '<dt>' . esc_html__( 'Who changes the WP-Cron lock', 'nightward' ) . '</dt><dd><ul class="nw-cron-locks">';
			foreach ( array_slice( array_reverse( $ls['log'] ), 0, 6 ) as $row ) {
				$who = 'check' === $row['how'] ? __( 'Nightward check', 'nightward' ) : ( 'core' === $row['component'] ? ( 'spawn' === $row['how'] ? __( 'WordPress (start of WP-Cron)', 'nightward' ) : ( 'wp-cron.php' === $row['how'] ? 'wp-cron.php' : 'WordPress' ) ) : Attribution::label( $row['component'] ) );
				echo '<li' . ( 'core' !== $row['component'] && 'nightward' !== $row['component'] ? ' class="nw-bad"' : '' ) . '>' . esc_html( $who ) . ( 'delete' === $row['op'] ? ' · ' . esc_html__( 'deleted', 'nightward' ) : '' ) . ( $row['file'] ? ' <code>' . esc_html( $row['file'] ) . '</code>' : '' ) . ' <span class="nw-muted">· ' . esc_html( $row['ctx'] ) . ' · ' . esc_html( sprintf( /* translators: %s: time */ __( '%s ago', 'nightward' ), human_time_diff( (int) $row['at'] ) ) ) . '</span></li>';
			}
			echo '</ul></dd>';
		}
		$si = Cron::server_info();
		echo '<dt>' . esc_html__( 'Server', 'nightward' ) . '</dt><dd>' . esc_html( ( $si['software'] ? $si['software'] : '?' ) . ' · PHP ' . PHP_VERSION . ' (' . $si['sapi'] . ')' ) . '</dd>';
		$oc = Cron::object_cache();
		echo '<dt>' . esc_html__( 'Object cache', 'nightward' ) . '</dt><dd>' . ( $oc['dropin'] ? esc_html( $oc['dropin'] ) . ( $oc['active'] ? '' : ' <span class="nw-muted">(' . esc_html__( 'drop-in present but not active', 'nightward' ) . ')</span>' ) : esc_html__( 'none (transients are stored in the database)', 'nightward' ) ) . '</dd>';
		if ( $h['prepend'] ) {
			echo '<dt>auto_prepend_file</dt><dd><code>' . esc_html( $h['prepend'] ) . '</code> <span class="nw-muted">' . esc_html__( 'runs before WordPress on every request', 'nightward' ) . '</span></dd>';
		}
		echo '<dt>DISABLE_WP_CRON</dt><dd>' . ( $h['disabled'] ? esc_html__( 'set (WordPress does not start WP-Cron by itself)', 'nightward' ) : esc_html__( 'not set', 'nightward' ) ) . '</dd>';
		echo '<dt>' . esc_html__( 'Backup scheduler', 'nightward' ) . '</dt><dd>';
		if ( ! $h['fallback'] ) {
			echo esc_html__( 'off', 'nightward' );
		} elseif ( $h['fallback_last'] ) {
			/* translators: %s: time */
			echo esc_html( sprintf( __( 'on, last ran Nightward\'s own tasks %s ago', 'nightward' ), human_time_diff( $h['fallback_last'] ) ) );
		} else {
			echo esc_html__( 'on, not needed so far', 'nightward' );
		}
		echo '</dd>';
		if ( $test ) {
			echo '<dt>' . esc_html__( 'Connection check', 'nightward' ) . '</dt><dd>' . ( in_array( $test['verdict'], array( 'ok', 'slow' ), true ) ? esc_html__( 'passed', 'nightward' ) : '<b class="nw-bad">' . esc_html__( 'failed', 'nightward' ) . '</b>' ) . ' <span class="nw-muted">· ' . esc_html( sprintf( /* translators: %s: time */ __( '%s ago', 'nightward' ), human_time_diff( $test['checked'] ) ) ) . ( $test['code'] ? ' · HTTP ' . (int) $test['code'] : '' ) . ' · ' . (int) $test['ms'] . ' ms</span></dd>';
		}
		echo '</dl>';

		$why = Cron::diagnosis( $h, $test );
		if ( $h['stale'] || $test ) {
			if ( $why ) {
				echo '<div class="nw-cron-why"><b>' . esc_html__( 'Why', 'nightward' ) . '</b>';
				foreach ( $why as $w ) {
					echo '<p>' . esc_html( $w ) . '</p>';
				}
				echo '</div>';
			} else {
				echo '<p class="nw-muted">' . esc_html__( 'Run the check: it starts WP-Cron the way WordPress does and shows where it stops.', 'nightward' ) . '</p>';
			}
		}

		if ( $test && 'killed' === $test['verdict'] && ! empty( $test['server']['litespeed'] ) ) {
			echo '<pre class="nw-pre">' . esc_html( "<IfModule LiteSpeed>\nRewriteEngine On\nRewriteRule .* - [E=noabort:1,E=noconntimeout:1]\n</IfModule>" ) . '</pre>';
		}
		echo '<p class="nw-actions"><button type="button" class="button" data-nw-cron-test>' . esc_html__( 'Start and check WP-Cron', 'nightward' ) . '</button>';
		if ( $own ) {
			echo ' <button type="button" class="button" data-nw-cron-run>' . esc_html__( 'Run Nightward tasks now', 'nightward' ) . '</button>';
		}
		echo ' <span class="nw-inline-status" data-nw-status></span></p>';
		echo '<p class="nw-note">' . esc_html__( 'The check starts WP-Cron exactly the way WordPress does and waits for the answer, so waiting tasks really run. It can take up to a minute.', 'nightward' ) . '</p>';

		if ( $h['fallback'] && $h['stale'] ) {
			echo '<p class="nw-note">' . esc_html__( 'Until WP-Cron works, Nightward runs its own report and checks when someone opens the site or the dashboard. WordPress updates and other plugins still wait for WP-Cron.', 'nightward' ) . '</p>';
		}

		$cmd = Cron::server_commands();
		echo '<details class="nw-cron-fix"' . ( $h['stale'] ? ' open' : '' ) . '><summary>' . esc_html__( 'Reliable fix: a server cron job', 'nightward' ) . '</summary>';
		echo '<p>' . esc_html__( 'In the hosting control panel, open Cron jobs (Scheduler) and add a task that runs every 5 minutes with one of these commands. WP-Cron then no longer depends on visits or on the site reaching itself.', 'nightward' ) . '</p>';
		echo '<pre class="nw-pre">' . esc_html( $cmd['curl'] ) . "\n" . esc_html( $cmd['wget'] ) . "\n" . esc_html( $cmd['cli'] ) . '</pre>';
		echo '<p>' . esc_html__( 'Once the job runs, you can add this line to wp-config.php so that page views stop starting WP-Cron:', 'nightward' ) . ' <code>define( \'DISABLE_WP_CRON\', true );</code></p>';
		echo '</details>';
		echo '</section>';
	}

	/* ================================================================== */
	/* Layout                                                             */
	/* ================================================================== */

	public static function tabs() {
		return array(
			'overview'  => __( 'Overview', 'nightward' ),
			'events'    => __( 'Events', 'nightward' ),
			'network'   => __( 'Network', 'nightward' ),
			'hooks'     => __( 'Hooks & Cron', 'nightward' ),
			'integrity' => __( 'Integrity', 'nightward' ),
			'hardening' => __( 'Hardening', 'nightward' ),
			'export'    => __( 'AI export', 'nightward' ),
			'settings'  => __( 'Settings', 'nightward' ),
		);
	}

	public static function render() {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'overview'; // phpcs:ignore WordPress.Security.NonceVerification
		$tabs = self::tabs();
		$tab  = isset( $tabs[ $tab ] ) ? $tab : 'overview';
		$c    = Events::open_counts();
		echo '<div class="wrap nw">';
		echo '<header class="nw-head"><div class="nw-brand"><span class="nw-logo" aria-hidden="true"></span><span>Nightward</span><span class="nw-ver">' . esc_html( NIGHTWARD_VERSION ) . '</span></div>';
		echo '<nav class="nw-tabs">';
		foreach ( $tabs as $k => $label ) {
			$count = '';
			if ( 'events' === $k && ( $c['critical'] + $c['high'] ) ) {
				$count = ' <span class="nw-count">' . (int) ( $c['critical'] + $c['high'] ) . '</span>';
			}
			printf( '<a href="%s" class="%s">%s%s</a>', esc_url( self::url( $k ) ), $k === $tab ? 'is-active' : '', esc_html( $label ), $count ); // phpcs:ignore
		}
		echo '</nav></header>';
		// Порожній h1/h2 — щоб WP вставляв повідомлення сюди, а не всередину карток.
		echo '<h1 class="nw-sr">Nightward</h1><hr class="wp-header-end">';
		if ( isset( $_GET['saved'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			echo '<div class="nw-flash">' . esc_html__( 'Settings saved.', 'nightward' ) . '</div>';
		}
		call_user_func( array( __CLASS__, 'tab_' . $tab ) );
		echo '</div>';
	}

	private static function pill( $sev ) {
		return '<span class="nw-pill nw-' . esc_attr( $sev ) . '">' . esc_html( Events::severity_label( $sev ) ) . '</span>';
	}

	private static function status_label( $s ) {
		$l = array(
			'open'         => __( 'Open', 'nightward' ),
			'acknowledged' => __( 'Acknowledged', 'nightward' ),
			'resolved'     => __( 'Resolved', 'nightward' ),
			'ignored'      => __( 'Ignored', 'nightward' ),
		);
		return isset( $l[ $s ] ) ? $l[ $s ] : $s;
	}

	private static function where( $r ) {
		$out = '';
		if ( $r->component && 'core' !== $r->component ) {
			$out .= '<span class="nw-comp">' . esc_html( Attribution::label( $r->component ) ) . '</span>';
		}
		if ( $r->file ) {
			$out .= '<code class="nw-file">' . esc_html( $r->file . ( $r->line ? ':' . $r->line : '' ) ) . '</code>';
		}
		return $out;
	}

	/* ================================================================== */
	/* Overview                                                           */
	/* ================================================================== */

	private static function tab_overview() {
		$c      = Events::open_counts();
		$worst  = $c['critical'] ? 'critical' : ( $c['high'] ? 'high' : ( $c['medium'] ? 'medium' : 'ok' ) );
		$titles = array(
			'critical' => __( 'Action required', 'nightward' ),
			'high'     => __( 'Needs your attention', 'nightward' ),
			'medium'   => __( 'A few things are worth a look', 'nightward' ),
			'ok'       => __( 'All clear', 'nightward' ),
		);
		$subs   = array(
			'critical' => __( 'Nightward found signs of compromise or dangerous changes. Start with the items below.', 'nightward' ),
			'high'     => __( 'There are findings that can mean a problem. Review them and mark what is expected.', 'nightward' ),
			'medium'   => __( 'Nothing urgent. Some findings are worth reviewing when you have a minute.', 'nightward' ),
			'ok'       => __( 'No open critical, high or medium findings. Monitors are running.', 'nightward' ),
		);
		$h = Cron::health();
		echo '<section class="nw-hero nw-hero-' . esc_attr( $worst ) . '"><div>';
		echo '<div class="nw-hero-kicker">' . esc_html__( 'Site status', 'nightward' ) . '</div>';
		echo '<div class="nw-hero-title">' . esc_html( $titles[ $worst ] ) . '</div>';
		echo '<p>' . esc_html( $subs[ $worst ] ) . '</p>';
		if ( Settings::in_learning() ) {
			$left = (int) get_option( 'nightward_installed_at' ) + HOUR_IN_SECONDS * (int) Settings::get( 'learning_hours', 24 ) - time();
			/* translators: %s: time left */
			echo '<p class="nw-learning">' . esc_html( sprintf( __( 'Learning mode: for the next %s Nightward records the normal behaviour of this site (hosts, hooks, scheduled tasks) without reporting it. Critical findings are still reported.', 'nightward' ), human_time_diff( time(), time() + max( 60, $left ) ) ) ) . '</p>';
		}
		echo '</div><div class="nw-counters">';
		foreach ( array( 'critical', 'high', 'medium', 'low' ) as $s ) {
			printf( '<a class="nw-counter nw-c-%1$s %4$s" href="%2$s"><b>%3$s</b><span>%5$s</span></a>', esc_attr( $s ), esc_url( self::url( 'events', array( 'severity' => $s, 'status' => 'open' ) ) ), (int) $c[ $s ], $c[ $s ] ? '' : 'is-zero', esc_html( Events::severity_label( $s ) ) );
		}
		echo '</div></section>';

		self::cron_panel();

		// Needs attention
		$top = Events::query( array( 'min_severity' => 'high', 'status' => 'open', 'limit' => 8, 'order' => 'severity' ) );
		echo '<div class="nw-grid"><section class="nw-card nw-span-2"><h2>' . esc_html__( 'Needs attention', 'nightward' ) . '</h2>';
		if ( ! $top ) {
			echo '<p class="nw-empty">' . esc_html__( 'Nothing critical or high is open.', 'nightward' ) . '</p>';
		} else {
			echo '<ul class="nw-list">';
			foreach ( $top as $r ) {
				echo '<li>' . self::pill( $r->severity ) . ' <a href="' . esc_url( self::url( 'events', array( 'event' => $r->id ) ) ) . '">' . esc_html( Events::title( $r ) ) . '</a>'; // phpcs:ignore
				echo '<div class="nw-meta">' . esc_html( Events::module_label( $r->module ) ) . ' · ' . esc_html( Util::ago( $r->last_seen ) ) . ' ' . self::where( $r ) . '</div></li>'; // phpcs:ignore
			}
			echo '</ul><p class="nw-actions"><a class="button" href="' . esc_url( self::url( 'events', array( 'status' => 'open' ) ) ) . '">' . esc_html__( 'All open events', 'nightward' ) . '</a> <a class="button-link" href="' . esc_url( self::url( 'export' ) ) . '">' . esc_html__( 'Ask an AI assistant about these findings', 'nightward' ) . '</a></p>';
		}
		echo '</section>';

		// Report card
		$ms = get_option( 'nightward_mail_status' );
		echo '<section class="nw-card"><h2>' . esc_html__( 'E-mail reports', 'nightward' ) . '</h2><dl class="nw-dl">';
		echo '<dt>' . esc_html__( 'Daily report', 'nightward' ) . '</dt><dd>' . ( Settings::get( 'report_enabled', 1 ) ? esc_html( sprintf( /* translators: %s: time */ __( 'every day at %s', 'nightward' ), Settings::get( 'report_time' ) ) ) : esc_html__( 'off', 'nightward' ) ) . '</dd>';
		echo '<dt>' . esc_html__( 'Next report', 'nightward' ) . '</dt><dd>' . ( $h['next_report'] ? esc_html( wp_date( 'j M, H:i', $h['next_report'] ) ) : '—' ) . '</dd>';
		echo '<dt>' . esc_html__( 'Last sent', 'nightward' ) . '</dt><dd>' . ( $h['last_report'] ? esc_html( wp_date( 'j M, H:i', $h['last_report'] ) ) : esc_html__( 'not yet', 'nightward' ) ) . '</dd>';
		echo '<dt>' . esc_html__( 'Instant alerts', 'nightward' ) . '</dt><dd>' . ( Settings::get( 'instant_enabled', 1 ) ? esc_html( 'critical' === Settings::get( 'instant_min_severity' ) ? __( 'critical only', 'nightward' ) : __( 'critical and high', 'nightward' ) ) : esc_html__( 'off', 'nightward' ) ) . '</dd>';
		echo '<dt>' . esc_html__( 'Recipient', 'nightward' ) . '</dt><dd>' . esc_html( Settings::report_email() ) . '</dd>';
		if ( is_array( $ms ) && ! $ms['ok'] ) {
			echo '<dt>' . esc_html__( 'Last error', 'nightward' ) . '</dt><dd class="nw-bad">' . esc_html( $ms['error'] ? $ms['error'] : __( 'wp_mail() returned false', 'nightward' ) ) . '</dd>';
		}
		echo '</dl><p class="nw-actions"><button type="button" class="button" data-nw-test-email>' . esc_html__( 'Send test report', 'nightward' ) . '</button> ';
		echo '<a class="button-link" target="_blank" href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=nightward_preview' ), 'nightward_preview' ) ) . '">' . esc_html__( 'Preview', 'nightward' ) . '</a> <span class="nw-inline-status" data-nw-status></span></p>';
		echo '</section></div>';

		// Modules
		echo '<h2 class="nw-h2">' . esc_html__( 'Monitors', 'nightward' ) . '</h2><div class="nw-modules">';
		foreach ( self::module_rows() as $m ) {
			printf(
				'<div class="nw-module %1$s"><div class="nw-module-top"><span class="nw-dot"></span><strong>%2$s</strong></div><p>%3$s</p><div class="nw-module-stat">%4$s</div></div>',
				$m['on'] ? 'is-on' : 'is-off',
				esc_html( $m['title'] ),
				esc_html( $m['desc'] ),
				wp_kses_post( $m['stat'] )
			);
		}
		echo '</div>';

		self::blind_spots();
	}

	private static function module_rows() {
		$net   = Outbound::stats_since( gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS ) );
		$int   = get_option( Integrity::LAST );
		$upl   = get_option( 'nightward_uploads_last' );
		$cron  = get_option( 'nightward_cron_stats' );
		$al    = get_option( 'nightward_autoload' );
		$score = Hardening::score();
		$hooks = 0;
		foreach ( Hooks_Watch::current_map() as $g ) {
			$hooks += count( $g );
		}
		$admins = count( Privilege_Guard::db_admins() );
		$upd    = get_site_transient( 'update_plugins' );
		$n_upd  = ! empty( $upd->response ) ? count( (array) $upd->response ) : 0;
		/* translators: %s: time ago */
		$ago = function ( $ts ) {
			return $ts ? sprintf( __( '%s ago', 'nightward' ), human_time_diff( $ts ) ) : __( 'not yet', 'nightward' );
		};
		return array(
			array( 'on' => Settings::enabled( 'outbound' ), 'title' => __( 'Outbound requests', 'nightward' ), 'desc' => __( 'Every HTTP request of the site, attributed to the plugin file and line that made it. Faked responses are traced to the exact callback.', 'nightward' ),
				/* translators: 1: hosts, 2: faked */
				'stat' => sprintf( __( '24 h: %1$d hosts · %2$d faked', 'nightward' ), $net['hosts'], $net['intercepted'] ) ),
			array( 'on' => Settings::enabled( 'hooks' ), 'title' => __( 'Sensitive hooks', 'nightward' ), 'desc' => __( 'Who can influence login, permissions, the users/plugins lists and the update channel. New callbacks and eval()-made code are reported.', 'nightward' ),
				/* translators: %d: count */
				'stat' => sprintf( __( '%d third-party callbacks watched', 'nightward' ), $hooks ) ),
			array( 'on' => Settings::enabled( 'privilege' ), 'title' => __( 'Users & privileges', 'nightward' ), 'desc' => __( 'Administrators created by code, via direct SQL or hidden from the Users list; credential changes, application passwords, logins from new networks.', 'nightward' ),
				/* translators: %d: count */
				'stat' => sprintf( _n( '%d administrator', '%d administrators', $admins, 'nightward' ), $admins ) ),
			array( 'on' => Settings::enabled( 'options' ), 'title' => __( 'Options', 'nightward' ), 'desc' => __( 'Site URL, admin e-mail, default role, role capabilities, plugin activation by code; options written on every page view; autoload weight.', 'nightward' ),
				/* translators: %s: size */
				'stat' => is_array( $al ) ? sprintf( __( 'autoload %s', 'nightward' ), Util::human_bytes( $al['total'] ) ) : '—' ),
			array( 'on' => Settings::enabled( 'cron' ), 'title' => __( 'Scheduled tasks', 'nightward' ), 'desc' => __( 'New WP-Cron tasks, random names, code in arguments, tasks without a handler.', 'nightward' ),
				/* translators: 1: tasks, 2: overdue */
				'stat' => is_array( $cron ) ? sprintf( __( '%1$d tasks · %2$d overdue', 'nightward' ), $cron['hooks'], $cron['overdue'] ) : '—' ),
			array( 'on' => Settings::enabled( 'integrity' ), 'title' => __( 'File integrity', 'nightward' ), 'desc' => __( 'Core and WordPress.org plugins against official checksums; premium plugins and themes against their own first snapshot.', 'nightward' ),
				/* translators: 1: files, 2: time */
				'stat' => is_array( $int ) ? sprintf( __( '%1$s files · %2$s', 'nightward' ), number_format_i18n( $int['files'] ), $ago( $int['finished'] ) ) : __( 'first scan pending', 'nightward' ) ),
			array( 'on' => Settings::enabled( 'uploads' ), 'title' => __( 'Executable files', 'nightward' ), 'desc' => __( 'Scripts in uploads, PHP hidden in images, .htaccess tricks, unknown files in wp-content and mu-plugins.', 'nightward' ),
				'stat' => is_array( $upl ) ? $ago( $upl['at'] ) : __( 'not yet', 'nightward' ) ),
			array( 'on' => Settings::enabled( 'update_channel' ), 'title' => __( 'Update channel', 'nightward' ), 'desc' => __( 'Where updates are downloaded from. Hijacked WordPress.org updates and packages from unrelated hosts are flagged or blocked.', 'nightward' ),
				/* translators: %d: count */
				'stat' => sprintf( _n( '%d update pending', '%d updates pending', $n_upd, 'nightward' ), $n_upd ) ),
			array( 'on' => Settings::enabled( 'hardening' ), 'title' => __( 'Hardening', 'nightward' ), 'desc' => __( 'Verified from outside: exposed backups and logs, PHP execution in uploads, XML-RPC, user enumeration, headers.', 'nightward' ),
				/* translators: %d: score */
				'stat' => null === $score ? '—' : sprintf( __( 'score %d / 100', 'nightward' ), $score ) ),
		);
	}

	private static function blind_spots() {
		echo '<section class="nw-card nw-blind"><h2>' . esc_html__( 'What Nightward cannot see', 'nightward' ) . '</h2><ul>';
		$items = array(
			__( 'Requests made with raw cURL, sockets or file_get_contents() bypass the WordPress HTTP API and are not logged.', 'nightward' ),
			__( 'Code that runs before Nightward starts: wp-config.php, drop-ins (db.php, advanced-cache.php, object-cache.php) and must-use plugins loaded before "0-nightward-early.php".', 'nightward' ),
			__( 'Direct database edits are found by the hourly audit, not at the moment they happen, and without the file that did it.', 'nightward' ),
			__( 'Premium plugins and themes are trusted as they are at the first scan. If they were already modified, only later changes are detected.', 'nightward' ),
			__( 'Nightward detects and reports; it is not a firewall. Someone with access to the server can disable any plugin, including this one — if the daily e-mail stops arriving, treat the silence as an alarm.', 'nightward' ),
		);
		foreach ( $items as $i ) {
			echo '<li>' . esc_html( $i ) . '</li>';
		}
		echo '</ul></section>';
	}

	/* ================================================================== */
	/* Events                                                             */
	/* ================================================================== */

	private static function tab_events() {
		// phpcs:disable WordPress.Security.NonceVerification
		$f = array(
			'severity' => isset( $_GET['severity'] ) ? sanitize_key( $_GET['severity'] ) : '',
			'module'   => isset( $_GET['module'] ) ? sanitize_key( $_GET['module'] ) : '',
			'status'   => isset( $_GET['status'] ) ? sanitize_key( $_GET['status'] ) : '',
			'search'   => isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '',
		);
		$event = isset( $_GET['event'] ) ? (int) $_GET['event'] : 0;
		$paged = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;
		// phpcs:enable

		// Bulk actions
		if ( isset( $_POST['nw_bulk'], $_POST['ids'] ) && check_admin_referer( 'nightward_bulk' ) ) {
			$n = Events::set_status( array_map( 'intval', (array) $_POST['ids'] ), sanitize_key( $_POST['nw_bulk'] ) );
			/* translators: %d: count */
			echo '<div class="nw-flash">' . esc_html( sprintf( _n( '%d event updated.', '%d events updated.', $n, 'nightward' ), $n ) ) . '</div>';
		}

		$per  = 40;
		$args = array_merge( $f, array( 'limit' => $per, 'offset' => ( $paged - 1 ) * $per ) );
		if ( '' === $f['status'] && ! $event ) {
			$args['status'] = array( 'open', 'acknowledged' );
		}
		$rows = $event ? array_filter( array( Events::get( $event ) ) ) : Events::query( $args );
		$total = $event ? count( $rows ) : Events::count( $args );

		echo '<form class="nw-filters" method="get"><input type="hidden" name="page" value="nightward"><input type="hidden" name="tab" value="events">';
		echo '<select name="severity"><option value="">' . esc_html__( 'All severities', 'nightward' ) . '</option>';
		foreach ( Events::SEVERITIES as $s ) {
			printf( '<option value="%s" %s>%s</option>', esc_attr( $s ), selected( $f['severity'], $s, false ), esc_html( Events::severity_label( $s ) ) );
		}
		echo '</select><select name="module"><option value="">' . esc_html__( 'All areas', 'nightward' ) . '</option>';
		foreach ( array( 'outbound', 'interception', 'hooks', 'privilege', 'options', 'cron', 'integrity', 'uploads', 'update_channel', 'hardening', 'system' ) as $m ) {
			printf( '<option value="%s" %s>%s</option>', esc_attr( $m ), selected( $f['module'], $m, false ), esc_html( Events::module_label( $m ) ) );
		}
		echo '</select><select name="status"><option value="">' . esc_html__( 'Open & acknowledged', 'nightward' ) . '</option>';
		foreach ( array( 'open', 'acknowledged', 'resolved', 'ignored' ) as $s ) {
			printf( '<option value="%s" %s>%s</option>', esc_attr( $s ), selected( $f['status'], $s, false ), esc_html( self::status_label( $s ) ) );
		}
		echo '</select><input type="search" name="s" value="' . esc_attr( $f['search'] ) . '" placeholder="' . esc_attr__( 'Search title, file, plugin…', 'nightward' ) . '"><button class="button">' . esc_html__( 'Filter', 'nightward' ) . '</button>';
		if ( $event || array_filter( $f ) ) {
			echo ' <a class="button-link" href="' . esc_url( self::url( 'events' ) ) . '">' . esc_html__( 'Reset', 'nightward' ) . '</a>';
		}
		echo '<a class="button-link nw-push" href="' . esc_url( self::url( 'export' ) ) . '">' . esc_html__( 'Export for AI analysis', 'nightward' ) . '</a>';
		echo '</form>';

		if ( ! $rows ) {
			echo '<section class="nw-card"><p class="nw-empty">' . esc_html__( 'No events match.', 'nightward' ) . '</p></section>';
			return;
		}

		echo '<form method="post" class="nw-card nw-table-card">';
		wp_nonce_field( 'nightward_bulk' );
		echo '<div class="nw-bulk"><select name="nw_bulk"><option value="acknowledged">' . esc_html__( 'Mark as acknowledged', 'nightward' ) . '</option><option value="resolved">' . esc_html__( 'Mark as resolved', 'nightward' ) . '</option><option value="ignored">' . esc_html__( 'Ignore (never report again)', 'nightward' ) . '</option><option value="open">' . esc_html__( 'Reopen', 'nightward' ) . '</option></select><button class="button">' . esc_html__( 'Apply', 'nightward' ) . '</button>';
		/* translators: %d: count */
		echo '<span class="nw-total">' . esc_html( sprintf( _n( '%d event', '%d events', $total, 'nightward' ), $total ) ) . '</span></div>';
		echo '<table class="nw-table nw-events"><thead><tr><th class="nw-cb"><input type="checkbox" data-nw-all></th><th>' . esc_html__( 'Severity', 'nightward' ) . '</th><th>' . esc_html__( 'Event', 'nightward' ) . '</th><th>' . esc_html__( 'Area', 'nightward' ) . '</th><th>' . esc_html__( 'Seen', 'nightward' ) . '</th><th>' . esc_html__( 'Status', 'nightward' ) . '</th><th></th></tr></thead><tbody>';
		foreach ( $rows as $r ) {
			$d    = Events::details( $r );
			$open = $event === (int) $r->id;
			echo '<tr class="nw-row' . ( $open ? ' is-open' : '' ) . '" data-nw-row="' . (int) $r->id . '">';
			echo '<td class="nw-cb"><input type="checkbox" name="ids[]" value="' . (int) $r->id . '"></td>';
			echo '<td>' . self::pill( $r->severity ) . '</td>'; // phpcs:ignore
			echo '<td><div class="nw-title">' . esc_html( Events::title( $r ) ) . '</div><div class="nw-meta">' . self::where( $r ) . '</div></td>'; // phpcs:ignore
			echo '<td class="nw-muted">' . esc_html( Events::module_label( $r->module ) ) . '</td>';
			echo '<td class="nw-muted" title="' . esc_attr( Util::local_time( $r->first_seen ) ) . '">' . esc_html( Util::ago( $r->last_seen ) ) . ( $r->hits > 1 ? '<br><small>× ' . (int) $r->hits . '</small>' : '' ) . '</td>';
			echo '<td><span class="nw-status nw-st-' . esc_attr( $r->status ) . '">' . esc_html( self::status_label( $r->status ) ) . '</span></td>';
			echo '<td><button type="button" class="button-link" data-nw-toggle="' . (int) $r->id . '">' . esc_html( $open ? __( 'Hide', 'nightward' ) : __( 'Details', 'nightward' ) ) . '</button></td></tr>';
			echo '<tr class="nw-detail" data-nw-detail="' . (int) $r->id . '"' . ( $open ? '' : ' hidden' ) . '><td></td><td colspan="6">';
			if ( ! empty( $d['explanation'] ) ) {
				echo '<p class="nw-explain">' . esc_html( Events::text( $d['explanation'] ) ) . '</p>';
			}
			echo '<dl class="nw-kv">';
			foreach ( Reports::detail_pairs( $d ) as $k => $v ) {
				echo '<dt>' . esc_html( $k ) . '</dt><dd>' . esc_html( $v ) . '</dd>';
			}
			echo '<dt>' . esc_html__( 'First seen', 'nightward' ) . '</dt><dd>' . esc_html( Util::local_time( $r->first_seen ) ) . '</dd>';
			echo '<dt>' . esc_html__( 'Last seen', 'nightward' ) . '</dt><dd>' . esc_html( Util::local_time( $r->last_seen ) ) . '</dd>';
			echo '</dl>';
			if ( 'outbound' === $r->module && in_array( $r->type, array( 'new_host', 'suspicious_destination' ), true ) ) {
				$host = Util::host_of( isset( $d['url'] ) ? $d['url'] : '' );
				if ( $host ) {
					echo '<p><button type="button" class="button button-small" data-nw-trust="' . esc_attr( Util::registrable( $host ) ) . '">' . esc_html( sprintf( /* translators: %s: domain */ __( 'Trust %s', 'nightward' ), Util::registrable( $host ) ) ) . '</button></p>';
				}
			}
			echo '</td></tr>';
		}
		echo '</tbody></table></form>';

		$pages = (int) ceil( $total / $per );
		if ( $pages > 1 && ! $event ) {
			echo '<div class="nw-pager">';
			for ( $p = 1; $p <= $pages; $p++ ) {
				printf( '<a class="%s" href="%s">%d</a>', $p === $paged ? 'is-active' : '', esc_url( add_query_arg( array_merge( array_filter( $f ), array( 'paged' => $p, 's' => $f['search'] ) ), self::url( 'events' ) ) ), (int) $p );
			}
			echo '</div>';
		}
	}

	/* ================================================================== */
	/* Network                                                            */
	/* ================================================================== */

	private static function tab_network() {
		$rows    = Outbound::rows( 30, 400 );
		$trusted = Settings::trusted_hosts();
		echo '<section class="nw-card nw-intro"><p>' . esc_html__( 'Every host this site contacted in the last 30 days through the WordPress HTTP API, grouped by the plugin or theme that made the request. "Faked" means a callback returned a response without the request ever leaving the server.', 'nightward' ) . '</p></section>';

		// Current interceptors
		global $wp_filter;
		$ic = array();
		if ( ! empty( $wp_filter['pre_http_request'] ) ) {
			foreach ( $wp_filter['pre_http_request']->callbacks as $prio => $cbs ) {
				foreach ( $cbs as $cid => $cb ) {
					if ( 0 === strpos( (string) $cid, 'nightward_s_' ) ) {
						continue;
					}
					$i = Attribution::callback_info( $cb['function'] );
					if ( in_array( $i['component'], array( 'nightward', 'core' ), true ) ) {
						continue;
					}
					$i['priority'] = $prio;
					$ic[]          = $i;
				}
			}
		}
		echo '<section class="nw-card"><h2>' . esc_html__( 'Code that can fake HTTP responses', 'nightward' ) . '</h2>';
		if ( ! $ic ) {
			echo '<p class="nw-empty">' . esc_html__( 'No plugin or theme is attached to pre_http_request in this request.', 'nightward' ) . '</p>';
		} else {
			echo '<table class="nw-table"><thead><tr><th>' . esc_html__( 'Plugin / theme', 'nightward' ) . '</th><th>' . esc_html__( 'Callback', 'nightward' ) . '</th><th>' . esc_html__( 'Location', 'nightward' ) . '</th><th>' . esc_html__( 'Priority', 'nightward' ) . '</th></tr></thead><tbody>';
			foreach ( $ic as $i ) {
				echo '<tr><td>' . esc_html( Attribution::label( $i['component'] ) ) . '</td><td><code>' . esc_html( $i['name'] ) . '</code></td><td><code class="nw-file">' . esc_html( $i['file'] . ':' . $i['line'] ) . '</code></td><td>' . (int) $i['priority'] . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</section>';

		echo '<section class="nw-card nw-table-card"><h2>' . esc_html__( 'Destinations', 'nightward' ) . '</h2>';
		if ( ! $rows ) {
			echo '<p class="nw-empty">' . esc_html__( 'No outbound requests recorded yet.', 'nightward' ) . '</p></section>';
			return;
		}
		echo '<table class="nw-table"><thead><tr><th>' . esc_html__( 'Host', 'nightward' ) . '</th><th>' . esc_html__( 'Requested by', 'nightward' ) . '</th><th class="num">' . esc_html__( 'Requests', 'nightward' ) . '</th><th class="num">' . esc_html__( 'Faked', 'nightward' ) . '</th><th class="num">' . esc_html__( 'Errors', 'nightward' ) . '</th><th>' . esc_html__( 'First seen', 'nightward' ) . '</th><th>' . esc_html__( 'Last seen', 'nightward' ) . '</th><th></th></tr></thead><tbody>';
		foreach ( $rows as $r ) {
			$reg   = Util::registrable( $r->host );
			$flag  = Util::bad_host_reason( $r->host ) ? 'nw-flag-bad' : ( in_array( $reg, Util::infra_hosts(), true ) ? 'nw-flag-infra' : '' );
			$is_tr = in_array( $reg, $trusted, true ) || in_array( $r->host, $trusted, true );
			echo '<tr class="' . esc_attr( $flag ) . '"><td><code title="' . esc_attr( $r->sample_url ) . '">' . esc_html( $r->host ) . '</code></td>';
			echo '<td>' . esc_html( Attribution::label( $r->component ) ) . '</td>';
			echo '<td class="num">' . (int) $r->hits . '</td><td class="num">' . ( $r->intercepted ? '<b class="nw-bad">' . (int) $r->intercepted . '</b>' : '0' ) . '</td><td class="num">' . (int) $r->errors . '</td>';
			echo '<td class="nw-muted">' . esc_html( Util::local_time( $r->first_seen, 'j M' ) ) . '</td><td class="nw-muted">' . esc_html( Util::ago( $r->last_seen ) ) . '</td>';
			echo '<td>' . ( $is_tr || Util::is_own_host( $r->host ) ? '<span class="nw-muted">' . esc_html__( 'Trusted', 'nightward' ) . '</span>' : '<button type="button" class="button-link" data-nw-trust="' . esc_attr( $reg ) . '">' . esc_html__( 'Trust', 'nightward' ) . '</button>' ) . '</td></tr>';
		}
		echo '</tbody></table></section>';
	}

	/* ================================================================== */
	/* Hooks & Cron                                                       */
	/* ================================================================== */

	private static function tab_hooks() {
		$map = Hooks_Watch::current_map();
		echo '<section class="nw-card nw-intro"><p>' . esc_html__( 'Third-party code attached to the hooks that decide who is logged in, what users may do, what the administrator sees and where updates and mail go. Core callbacks are not listed. A plugin here is not bad by itself — security, membership and SMTP plugins must hook in — but you should recognise every line.', 'nightward' ) . '</p></section>';
		foreach ( array( 'auth', 'conceal', 'channel' ) as $g ) {
			echo '<section class="nw-card"><h2>' . esc_html( ucfirst( Hooks_Watch::group_label( $g ) ) ) . '</h2>';
			if ( empty( $map[ $g ] ) ) {
				echo '<p class="nw-empty">' . esc_html__( 'Only WordPress core.', 'nightward' ) . '</p></section>';
				continue;
			}
			echo '<table class="nw-table"><thead><tr><th>' . esc_html__( 'Hook', 'nightward' ) . '</th><th>' . esc_html__( 'Plugin / theme', 'nightward' ) . '</th><th>' . esc_html__( 'Callback', 'nightward' ) . '</th><th>' . esc_html__( 'Location', 'nightward' ) . '</th></tr></thead><tbody>';
			foreach ( $map[ $g ] as $i ) {
				$bad = 'eval' === $i['component'];
				echo '<tr' . ( $bad ? ' class="nw-flag-bad"' : '' ) . '><td><code>' . esc_html( $i['hook'] ) . '</code></td><td>' . esc_html( Attribution::label( $i['component'] ) ) . '</td><td><code>' . esc_html( $i['name'] ) . '</code></td><td><code class="nw-file">' . esc_html( $i['file'] . ':' . $i['line'] ) . '</code></td></tr>';
			}
			echo '</tbody></table></section>';
		}

		$rows = Cron_Guard::table();
		echo '<section class="nw-card nw-table-card"><h2>' . esc_html__( 'Scheduled tasks', 'nightward' ) . '</h2>';
		echo '<table class="nw-table"><thead><tr><th>' . esc_html__( 'Task', 'nightward' ) . '</th><th>' . esc_html__( 'Runs', 'nightward' ) . '</th><th>' . esc_html__( 'Next run', 'nightward' ) . '</th><th>' . esc_html__( 'Handler', 'nightward' ) . '</th></tr></thead><tbody>';
		foreach ( $rows as $r ) {
			$cls = $r['random'] || $r['bad_args'] ? 'nw-flag-bad' : ( 'none' === $r['component'] ? 'nw-flag-dim' : '' );
			echo '<tr class="' . esc_attr( $cls ) . '"><td><code>' . esc_html( $r['hook'] ) . '</code>' . ( $r['bad_args'] ? '<div class="nw-bad">' . esc_html( $r['bad_args'] ) . '</div>' : '' ) . '</td>';
			echo '<td class="nw-muted">' . esc_html( $r['schedule'] ? $r['schedule'] : __( 'once', 'nightward' ) ) . ( $r['count'] > 1 ? ' × ' . (int) $r['count'] : '' ) . '</td>';
			echo '<td class="nw-muted">' . esc_html( $r['next'] < time() ? __( 'overdue', 'nightward' ) : wp_date( 'j M H:i', $r['next'] ) ) . '</td>';
			echo '<td>' . ( 'none' === $r['component'] ? '<span class="nw-muted">' . esc_html__( 'no handler (leftover of a removed plugin?)', 'nightward' ) . '</span>' : esc_html( Attribution::label( $r['component'] ) ) . ' <code class="nw-file">' . esc_html( $r['file'] . ':' . $r['line'] ) . '</code>' ) . '</td></tr>';
		}
		echo '</tbody></table></section>';
	}

	/* ================================================================== */
	/* Integrity                                                          */
	/* ================================================================== */

	private static function tab_integrity() {
		$st   = Integrity::status();
		$last = $st['last'];
		echo '<section class="nw-card nw-scan"><div><h2>' . esc_html__( 'File integrity', 'nightward' ) . '</h2>';
		if ( $last ) {
			/* translators: 1: files, 2: time ago, 3: problems */
			echo '<p>' . esc_html( sprintf( _n( 'Last scan: %1$s files, %2$s, %3$d problem found.', 'Last scan: %1$s files, %2$s, %3$d problems found.', (int) $last['problems'], 'nightward' ), number_format_i18n( $last['files'] ), sprintf( __( '%s ago', 'nightward' ), human_time_diff( $last['finished'] ) ), $last['problems'] ) ) . '</p>';
		} else {
			echo '<p>' . esc_html__( 'No scan finished yet.', 'nightward' ) . '</p>';
		}
		/* translators: %s: time */
		echo '<p class="nw-muted">' . esc_html( sprintf( __( 'Runs automatically every day at %s in small batches.', 'nightward' ), Settings::get( 'integrity_time' ) ) ) . '</p></div>';
		echo '<div class="nw-scan-actions"><button type="button" class="button button-primary" data-nw-scan>' . esc_html__( 'Scan now', 'nightward' ) . '</button><div class="nw-progress" hidden><div class="nw-bar"><span></span></div><div class="nw-progress-text"></div></div></div></section>';

		$mode_label = array(
			'core'     => array( 'ok', __( 'Official checksums', 'nightward' ) ),
			'wporg'    => array( 'ok', __( 'WordPress.org checksums', 'nightward' ) ),
			'tofu'     => array( 'tofu', __( 'Own snapshot', 'nightward' ) ),
			'baseline' => array( 'new', __( 'Snapshot taken', 'nightward' ) ),
		);
		$verified = $last ? (array) $last['verified'] : array();
		$open     = array();
		foreach ( Events::query( array( 'module' => 'integrity', 'status' => array( 'open', 'acknowledged' ), 'limit' => 500 ) ) as $e ) {
			$open[ $e->component ][] = $e;
		}
		echo '<section class="nw-card nw-table-card"><table class="nw-table"><thead><tr><th>' . esc_html__( 'Package', 'nightward' ) . '</th><th>' . esc_html__( 'Version', 'nightward' ) . '</th><th>' . esc_html__( 'Verified against', 'nightward' ) . '</th><th>' . esc_html__( 'Problems', 'nightward' ) . '</th><th></th></tr></thead><tbody>';
		foreach ( Integrity::packages() as $p ) {
			$m  = isset( $verified[ $p['id'] ] ) ? $verified[ $p['id'] ] : '';
			$ml = isset( $mode_label[ $m ] ) ? $mode_label[ $m ] : array( 'none', __( 'not scanned yet', 'nightward' ) );
			$n  = isset( $open[ $p['id'] ] ) ? count( $open[ $p['id'] ] ) : 0;
			echo '<tr><td><strong>' . esc_html( $p['name'] ) . '</strong><div class="nw-meta">' . esc_html( ucfirst( $p['type'] ) ) . '</div></td><td>' . esc_html( $p['version'] ) . '</td>';
			echo '<td><span class="nw-tag nw-tag-' . esc_attr( $ml[0] ) . '">' . esc_html( $ml[1] ) . '</span></td>';
			echo '<td>' . ( $n ? '<a class="nw-bad" href="' . esc_url( self::url( 'events', array( 'module' => 'integrity', 's' => '' ) ) ) . '">' . (int) $n . '</a>' : '<span class="nw-muted">0</span>' ) . '</td>';
			echo '<td>' . ( $n && in_array( $m, array( 'tofu', 'baseline' ), true ) ? '<button type="button" class="button-link" data-nw-accept="' . esc_attr( $p['id'] ) . '">' . esc_html__( 'Accept current files', 'nightward' ) . '</button>' : '' ) . '</td></tr>';
		}
		echo '</tbody></table></section>';
		echo '<p class="nw-note">' . esc_html__( '"Own snapshot" means the package is not on WordPress.org, so Nightward compares it with the state recorded at the first scan. Changes that come with a version bump are treated as updates; changes without one are reported.', 'nightward' ) . '</p>';
	}

	/* ================================================================== */
	/* Hardening                                                          */
	/* ================================================================== */

	private static function tab_hardening() {
		$r     = Hardening::results();
		$score = Hardening::score();
		echo '<section class="nw-card nw-scan"><div><h2>' . esc_html__( 'Hardening', 'nightward' ) . '</h2>';
		echo '<p>' . ( $r ? esc_html( sprintf( /* translators: %s: time ago */ __( 'Checked %s ago.', 'nightward' ), human_time_diff( $r['at'] ) ) ) : esc_html__( 'Not checked yet.', 'nightward' ) ) . '</p>';
		echo '<p class="nw-muted">' . esc_html__( 'Where it matters, checks are done the way an attacker would: by requesting the file from outside.', 'nightward' ) . '</p></div>';
		echo '<div class="nw-scan-actions">' . ( null !== $score ? '<div class="nw-score"><b>' . (int) $score . '</b><span>/ 100</span></div>' : '' ) . '<button type="button" class="button button-primary" data-nw-hardening>' . esc_html__( 'Run checks', 'nightward' ) . '</button> <span class="nw-inline-status" data-nw-status></span></div></section>';
		if ( ! $r ) {
			return;
		}
		$order = array( 'fail' => 0, 'warn' => 1, 'skip' => 2, 'pass' => 3 );
		$list  = $r['results'];
		usort( $list, function ( $a, $b ) use ( $order ) {
			return $order[ $a['status'] ] - $order[ $b['status'] ];
		} );
		echo '<section class="nw-card"><ul class="nw-checks">';
		foreach ( $list as $x ) {
			echo '<li class="nw-check nw-check-' . esc_attr( $x['status'] ) . '"><span class="nw-check-icon" aria-hidden="true"></span><div><div class="nw-check-title">' . esc_html( Events::text( $x['title'] ) ) . '</div>';
			if ( $x['detail'] ) {
				echo '<div class="nw-check-detail">' . esc_html( Events::text( $x['detail'] ) ) . '</div>';
			}
			if ( $x['fix'] && 'pass' !== $x['status'] ) {
				$is_code = (bool) preg_match( '/^(define|chmod|Options|<|location)|[;{}]\s*$/', $x['fix'] );
				echo $is_code ? '<code class="nw-fix">' . esc_html( Events::tr( $x['fix'] ) ) . '</code>' : '<div class="nw-check-fix">→ ' . esc_html( Events::tr( $x['fix'] ) ) . '</div>';
			}
			echo '</div></li>';
		}
		echo '</ul></section>';
	}

	/* ================================================================== */
	/* Settings                                                           */
	/* ================================================================== */

	private static function field_check( $key, $label, $desc = '' ) {
		printf( '<label class="nw-switch"><input type="checkbox" name="nw[%1$s]" value="1" %2$s><span class="nw-switch-ui"></span><span class="nw-switch-text"><b>%3$s</b>%4$s</span></label>', esc_attr( $key ), checked( (int) Settings::get( $key ), 1, false ), esc_html( $label ), $desc ? '<small>' . esc_html( $desc ) . '</small>' : '' );
	}

	/* ================================================================== */
	/* AI export                                                          */
	/* ================================================================== */

	private static function tab_export() {
		$d = Export::defaults();
		echo '<section class="nw-card nw-export"><h2>' . esc_html__( 'Export for AI analysis', 'nightward' ) . '</h2>';
		echo '<p class="nw-lead">' . esc_html__( 'One file with everything an AI assistant needs to review this site: instructions for the assistant, site context, findings with file and line, installed plugins and themes, outbound hosts, sensitive hooks, scheduled tasks, hardening and integrity results. Download it or copy it, paste it into ChatGPT, Claude, Gemini or another assistant, and ask your question. No need to explain what the file is.', 'nightward' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" data-nw-export>';
		wp_nonce_field( 'nightward_export' );
		echo '<input type="hidden" name="action" value="nightward_export">';
		echo '<div class="nw-row2">';
		echo '<label><span>' . esc_html__( 'Format', 'nightward' ) . '</span><select name="format" id="nw-export-format"><option value="md">' . esc_html__( 'Markdown (.md) - best for chat', 'nightward' ) . '</option><option value="json">' . esc_html__( 'JSON (.json) - structured', 'nightward' ) . '</option></select></label>';
		echo '<label><span>' . esc_html__( 'Period', 'nightward' ) . '</span><select name="days" id="nw-export-days">';
		foreach ( array( 7 => __( 'Last 7 days', 'nightward' ), 30 => __( 'Last 30 days', 'nightward' ), 90 => __( 'Last 90 days', 'nightward' ), 0 => __( 'All time', 'nightward' ) ) as $v => $l ) {
			printf( '<option value="%d" %s>%s</option>', (int) $v, selected( $d['days'], $v, false ), esc_html( $l ) );
		}
		echo '</select></label>';
		echo '<label><span>' . esc_html__( 'Findings', 'nightward' ) . '</span><select name="status" id="nw-export-status"><option value="active">' . esc_html__( 'Open and acknowledged', 'nightward' ) . '</option><option value="all">' . esc_html__( 'All, including resolved and ignored', 'nightward' ) . '</option></select></label>';
		echo '<label><span>' . esc_html__( 'Minimum severity', 'nightward' ) . '</span><select name="min_severity" id="nw-export-sev">';
		foreach ( Events::SEVERITIES as $sev ) {
			printf( '<option value="%s" %s>%s</option>', esc_attr( $sev ), selected( $d['min_severity'], $sev, false ), esc_html( Events::severity_label( $sev ) ) );
		}
		echo '</select></label></div>';
		echo '<label class="nw-switch"><input type="checkbox" name="inventory" value="1" checked><span class="nw-switch-ui"></span><span class="nw-switch-text"><b>' . esc_html__( 'Include site inventory', 'nightward' ) . '</b><small>' . esc_html__( 'Installed plugins and themes, outbound hosts, sensitive hooks and scheduled tasks. Lets the assistant confirm or dismiss findings.', 'nightward' ) . '</small></span></label>';
		echo '<label class="nw-switch"><input type="checkbox" name="redact" value="1" checked><span class="nw-switch-ui"></span><span class="nw-switch-text"><b>' . esc_html__( 'Hide the site address, e-mail and IP addresses', 'nightward' ) . '</b><small>' . esc_html__( 'Recommended before pasting into an online service. User logins, plugin names and file paths stay, because the analysis needs them.', 'nightward' ) . '</small></span></label>';
		echo '<p class="nw-actions"><button class="button button-primary">' . esc_html__( 'Download file', 'nightward' ) . '</button> <button type="button" class="button" data-nw-export-copy>' . esc_html__( 'Copy to clipboard', 'nightward' ) . '</button> <span class="nw-inline-status" data-nw-status></span></p>';
		echo '</form><textarea class="nw-export-text" readonly hidden aria-label="' . esc_attr__( 'Export text', 'nightward' ) . '"></textarea></section>';

		echo '<section class="nw-card"><h2>' . esc_html__( 'What the assistant is told', 'nightward' ) . '</h2>';
		echo '<p class="nw-muted">' . esc_html__( 'The file starts with these instructions, in English, so any assistant understands them. It is asked to answer in your WordPress language.', 'nightward' ) . '</p>';
		echo '<pre class="nw-pre">' . esc_html( Export::instructions() ) . '</pre>';
		echo '<p class="nw-muted">' . esc_html__( 'From the command line: wp nightward export > nightward.md', 'nightward' ) . '</p></section>';
	}

	private static function export_options_from_request() {
		// phpcs:disable WordPress.Security.NonceVerification -- verified by the callers
		$in = array(
			'format'       => isset( $_REQUEST['format'] ) ? sanitize_key( $_REQUEST['format'] ) : 'md',
			'days'         => isset( $_REQUEST['days'] ) ? (int) $_REQUEST['days'] : 30,
			'status'       => isset( $_REQUEST['status'] ) ? sanitize_key( $_REQUEST['status'] ) : 'active',
			'min_severity' => isset( $_REQUEST['min_severity'] ) ? sanitize_key( $_REQUEST['min_severity'] ) : 'low',
			'inventory'    => ! empty( $_REQUEST['inventory'] ),
			'redact'       => ! empty( $_REQUEST['redact'] ),
		);
		// phpcs:enable
		return Export::sanitize( $in );
	}

	public static function download_export() {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( '', 403 );
		}
		check_admin_referer( 'nightward_export' );
		$opt  = self::export_options_from_request();
		$text = Export::render( Export::build( $opt ), $opt['format'] );
		nocache_headers();
		header( 'Content-Type: ' . ( 'json' === $opt['format'] ? 'application/json' : 'text/markdown' ) . '; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . Export::filename( $opt ) . '"' );
		header( 'Content-Length: ' . strlen( $text ) );
		echo $text; // phpcs:ignore WordPress.Security.EscapeOutput -- file download
		exit;
	}

	public static function ajax_export_text() {
		self::guard();
		$opt = self::export_options_from_request();
		wp_send_json_success( array( 'text' => Export::render( Export::build( $opt ), $opt['format'] ) ) );
	}

	private static function tab_settings() {
		$s = Settings::all();
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="nw-settings">';
		wp_nonce_field( 'nightward_save' );
		echo '<input type="hidden" name="action" value="nightward_save">';

		echo '<section class="nw-card"><h2>' . esc_html__( 'Daily report', 'nightward' ) . '</h2>';
		self::field_check( 'report_enabled', __( 'Send a daily security report', 'nightward' ) );
		echo '<div class="nw-row2"><label><span>' . esc_html__( 'Time (site timezone)', 'nightward' ) . '</span><input type="time" name="nw[report_time]" value="' . esc_attr( $s['report_time'] ) . '"></label>';
		echo '<label><span>' . esc_html__( 'Recipients', 'nightward' ) . '</span><input type="text" name="nw[report_email]" value="' . esc_attr( $s['report_email'] ) . '" placeholder="' . esc_attr( get_option( 'admin_email' ) ) . '"><small>' . esc_html__( 'Comma-separated. Empty = site admin e-mail.', 'nightward' ) . '</small></label></div>';
		/* translators: %s: timezone */
		echo '<p class="nw-muted">' . esc_html( sprintf( __( 'Site timezone: %s. Change it in Settings → General.', 'nightward' ), wp_timezone_string() ) ) . '</p>';
		self::field_check( 'report_send_empty', __( 'Send the report even when nothing happened', 'nightward' ), __( 'Recommended. A missing "all clear" tells you that the site, WP-Cron or Nightward itself stopped working.', 'nightward' ) );
		echo '</section>';

		echo '<section class="nw-card"><h2>' . esc_html__( 'Instant alerts', 'nightward' ) . '</h2>';
		self::field_check( 'instant_enabled', __( 'E-mail immediately when something serious is detected', 'nightward' ) );
		echo '<div class="nw-row2"><label><span>' . esc_html__( 'Alert on', 'nightward' ) . '</span><select name="nw[instant_min_severity]"><option value="critical" ' . selected( $s['instant_min_severity'], 'critical', false ) . '>' . esc_html__( 'Critical only', 'nightward' ) . '</option><option value="high" ' . selected( $s['instant_min_severity'], 'high', false ) . '>' . esc_html__( 'Critical and high', 'nightward' ) . '</option></select></label>';
		echo '<label><span>' . esc_html__( 'Maximum alerts per hour', 'nightward' ) . '</span><input type="number" min="1" max="50" name="nw[instant_max_per_hour]" value="' . (int) $s['instant_max_per_hour'] . '"><small>' . esc_html__( 'Anything above is combined into one message.', 'nightward' ) . '</small></label></div>';
		echo '<p class="nw-actions"><button type="button" class="button" data-nw-test-email>' . esc_html__( 'Send test report', 'nightward' ) . '</button> <a class="button-link" target="_blank" href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=nightward_preview' ), 'nightward_preview' ) ) . '">' . esc_html__( 'Preview report', 'nightward' ) . '</a> <span class="nw-inline-status" data-nw-status></span></p>';
		echo '</section>';

		echo '<section class="nw-card"><h2>' . esc_html__( 'Monitors', 'nightward' ) . '</h2><div class="nw-switches">';
		self::field_check( 'mod_outbound', __( 'Outbound requests & HTTP interception', 'nightward' ) );
		self::field_check( 'mod_hooks', __( 'Sensitive hooks', 'nightward' ) );
		self::field_check( 'mod_privilege', __( 'Users & privileges', 'nightward' ) );
		self::field_check( 'mod_options', __( 'Options', 'nightward' ) );
		self::field_check( 'mod_cron', __( 'Scheduled tasks', 'nightward' ) );
		self::field_check( 'mod_integrity', __( 'File integrity', 'nightward' ) );
		self::field_check( 'mod_uploads', __( 'Executable files', 'nightward' ) );
		self::field_check( 'mod_update_channel', __( 'Update channel', 'nightward' ) );
		self::field_check( 'mod_hardening', __( 'Hardening checks', 'nightward' ) );
		echo '</div></section>';

		echo '<section class="nw-card"><h2>' . esc_html__( 'Advanced', 'nightward' ) . '</h2>';
		self::field_check( 'block_foreign_packages', __( 'Block updates downloaded from hosts unrelated to the plugin vendor', 'nightward' ), __( 'Hijacked WordPress.org updates and known malicious hosts are always blocked.', 'nightward' ) );
		self::field_check( 'mu_loader', __( 'Start before other plugins (must-use loader)', 'nightward' ), __( 'Lets Nightward see hooks and requests of plugins from their first line.', 'nightward' ) );
		self::field_check( 'cron_fallback', __( 'Run Nightward\'s tasks without WP-Cron when it fails', 'nightward' ), __( 'If WP-Cron has not fired for 15 minutes, the daily report and checks run during an ordinary request, after the page has been sent where the server allows it.', 'nightward' ) );
		echo '<div class="nw-row2"><label><span>' . esc_html__( 'Trusted hosts', 'nightward' ) . '</span><textarea name="nw[trusted_hosts]" rows="4" placeholder="example.com">' . esc_textarea( $s['trusted_hosts'] ) . '</textarea><small>' . esc_html__( 'One domain per line. Requests and update downloads to these are not reported.', 'nightward' ) . '</small></label>';
		echo '<div><label><span>' . esc_html__( 'Daily scan time', 'nightward' ) . '</span><input type="time" name="nw[integrity_time]" value="' . esc_attr( $s['integrity_time'] ) . '"></label>';
		echo '<label><span>' . esc_html__( 'Files per batch', 'nightward' ) . '</span><input type="number" min="50" max="3000" name="nw[integrity_batch]" value="' . (int) $s['integrity_batch'] . '"></label>';
		echo '<label><span>' . esc_html__( 'Learning period, hours', 'nightward' ) . '</span><input type="number" min="0" max="168" name="nw[learning_hours]" value="' . (int) $s['learning_hours'] . '"></label>';
		echo '<label><span>' . esc_html__( 'Keep resolved events, days', 'nightward' ) . '</span><input type="number" min="7" max="365" name="nw[retention_days]" value="' . (int) $s['retention_days'] . '"></label></div></div>';
		echo '</section>';

		echo '<p class="submit"><button class="button button-primary button-hero">' . esc_html__( 'Save settings', 'nightward' ) . '</button></p></form>';
		self::cron_panel( true );
	}

	public static function save_settings() {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( '', 403 );
		}
		check_admin_referer( 'nightward_save' );
		$in  = isset( $_POST['nw'] ) && is_array( $_POST['nw'] ) ? wp_unslash( $_POST['nw'] ) : array(); // phpcs:ignore
		$new = Settings::sanitize( $in );
		Settings::update( $new );
		if ( $new['mu_loader'] && ! Installer::loader_installed() ) {
			Installer::install_loader();
		} elseif ( ! $new['mu_loader'] ) {
			Installer::remove_loader();
		}
		Cron::schedule_all();
		wp_safe_redirect( self::url( 'settings', array( 'saved' => 1 ) ) );
		exit;
	}

	public static function preview_report() {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( '', 403 );
		}
		check_admin_referer( 'nightward_preview' );
		$d = Reports::collect( time() - DAY_IN_SECONDS );
		echo Reports::render_digest( $d, true ); // phpcs:ignore -- escaped inside
		exit;
	}

	/* ================================================================== */
	/* AJAX                                                               */
	/* ================================================================== */

	private static function guard() {
		if ( ! current_user_can( self::CAP ) || ! check_ajax_referer( 'nightward', 'nonce', false ) ) {
			wp_send_json_error( array( 'message' => __( 'Not allowed.', 'nightward' ) ), 403 );
		}
	}

	public static function ajax_cron_test() {
		self::guard();
		$r = Cron::loopback_test();
		wp_send_json_success( array( 'verdict' => $r['verdict'], 'text' => Cron::verdict_text( $r ) ) );
	}

	public static function ajax_cron_run() {
		self::guard();
		$n = Cron::run_due( Cron::own_overdue( 0 ), true, 'manual' );
		/* translators: %d: number of tasks */
		wp_send_json_success( array( 'ran' => $n, 'text' => sprintf( _n( '%d task done.', '%d tasks done.', $n, 'nightward' ), $n ) ) );
	}

	public static function ajax_status() {
		self::guard();
		wp_send_json_success( array( 'counts' => Events::open_counts() ) );
	}

	public static function ajax_integrity() {
		self::guard();
		if ( ! empty( $_POST['start'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			delete_option( Integrity::JOB );
			Integrity::start( true );
		}
		wp_send_json_success( Integrity::step( 8 ) );
	}

	public static function ajax_hardening() {
		self::guard();
		Hardening::run();
		wp_send_json_success( array( 'score' => Hardening::score() ) );
	}

	public static function ajax_test_email() {
		self::guard();
		$ok = Reports::send_digest( '', true );
		$ms = get_option( 'nightward_mail_status' );
		if ( $ok ) {
			wp_send_json_success();
		}
		wp_send_json_error( array( 'message' => is_array( $ms ) && $ms['error'] ? $ms['error'] : __( 'wp_mail() failed. Check the SMTP configuration of the site.', 'nightward' ) ) );
	}

	public static function ajax_trust_host() {
		self::guard();
		$host = isset( $_POST['host'] ) ? strtolower( sanitize_text_field( wp_unslash( $_POST['host'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		if ( ! $host || ! preg_match( '/^[a-z0-9.-]+$/', $host ) ) {
			wp_send_json_error();
		}
		$list   = Settings::trusted_hosts();
		$list[] = $host;
		Settings::update( array( 'trusted_hosts' => implode( "\n", array_unique( $list ) ) ) );
		global $wpdb;
		$t = DB::events();
		$wpdb->query( $wpdb->prepare( "UPDATE {$t} SET status = 'resolved' WHERE module = 'outbound' AND type IN ('new_host','suspicious_destination') AND status = 'open' AND (details LIKE %s OR details LIKE %s)", '%://' . $wpdb->esc_like( $host ) . '%', '%.' . $wpdb->esc_like( $host ) . '%' ) ); // phpcs:ignore
		wp_send_json_success();
	}

	public static function ajax_accept() {
		self::guard();
		$pkg = isset( $_POST['package'] ) ? sanitize_text_field( wp_unslash( $_POST['package'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		if ( ! $pkg ) {
			wp_send_json_error();
		}
		Integrity::accept( $pkg );
		wp_send_json_success();
	}
}
