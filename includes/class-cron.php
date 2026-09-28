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

	/** Is WP-Cron actually firing? Used on the dashboard. */
	public static function health() {
		$last = (int) get_option( 'nightward_last_hourly', 0 );
		return array(
			'disabled'    => defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON,
			'last_hourly' => $last,
			'stale'       => $last && ( time() - $last ) > 3 * HOUR_IN_SECONDS,
			'next_report' => wp_next_scheduled( 'nightward_daily_report' ),
			'last_report' => (int) get_option( 'nightward_last_report_sent', 0 ),
		);
	}
}
