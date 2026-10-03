<?php
/**
 * Settings: one small autoloaded option.
 */

namespace Nightward;

defined( 'ABSPATH' ) || exit;

class Settings {

	const OPTION = 'nightward_settings';

	private static $cache = null;

	public static function defaults() {
		return array(
			// Reports
			'report_enabled'       => 1,
			'report_email'         => '',          // empty = admin_email
			'report_time'          => '20:00',     // site timezone
			'report_send_empty'    => 1,           // send "all clear" too — silence must not look like a broken cron
			'instant_enabled'      => 1,
			'instant_min_severity' => 'critical',  // critical | high
			'instant_max_per_hour' => 5,
			// Modules
			'mod_outbound'         => 1,
			'mod_hooks'            => 1,
			'mod_privilege'        => 1,
			'mod_options'          => 1,
			'mod_cron'             => 1,
			'mod_integrity'        => 1,
			'mod_uploads'          => 1,
			'mod_update_channel'   => 1,
			'mod_hardening'        => 1,
			// Behaviour
			'learning_hours'       => 24,          // new hosts/hooks/cron after install are recorded silently
			'integrity_time'       => '03:30',
			'integrity_batch'      => 400,         // files per batch
			'block_foreign_packages' => 0,         // block updates downloaded from a host unrelated to the plugin
			'trusted_hosts'        => '',          // one per line
			'retention_days'       => 60,
			'mu_loader'            => 1,
			'cron_fallback'        => 1,           // run Nightward's own overdue tasks from ordinary requests
		);
	}

	public static function all() {
		if ( null === self::$cache ) {
			$stored      = get_option( self::OPTION, array() );
			self::$cache = wp_parse_args( is_array( $stored ) ? $stored : array(), self::defaults() );
		}
		return self::$cache;
	}

	public static function get( $key, $fallback = null ) {
		$all = self::all();
		return array_key_exists( $key, $all ) ? $all[ $key ] : $fallback;
	}

	public static function enabled( $module ) {
		return (bool) self::get( 'mod_' . $module, 1 );
	}

	public static function update( array $values ) {
		$new         = wp_parse_args( $values, self::all() );
		self::$cache = null;
		update_option( self::OPTION, $new, true );
		self::$cache = null;
	}

	public static function report_email() {
		$e = trim( (string) self::get( 'report_email', '' ) );
		return $e ? $e : get_option( 'admin_email' );
	}

	/** @return string[] */
	public static function trusted_hosts() {
		$lines = preg_split( '/[\s,]+/', strtolower( (string) self::get( 'trusted_hosts', '' ) ) );
		return array_values( array_filter( array_map( 'trim', $lines ) ) );
	}

	public static function sanitize( array $in ) {
		$d   = self::defaults();
		$out = array();
		foreach ( $d as $k => $def ) {
			if ( is_int( $def ) ) {
				$out[ $k ] = isset( $in[ $k ] ) ? max( 0, (int) $in[ $k ] ) : ( 0 === strpos( $k, 'mod_' ) || in_array( $k, array( 'report_enabled', 'report_send_empty', 'instant_enabled', 'block_foreign_packages', 'mu_loader', 'cron_fallback' ), true ) ? 0 : $def );
			} else {
				$out[ $k ] = isset( $in[ $k ] ) ? sanitize_textarea_field( wp_unslash( $in[ $k ] ) ) : $def;
			}
		}
		foreach ( array( 'report_time', 'integrity_time' ) as $t ) {
			if ( ! preg_match( '/^([01]?\d|2[0-3]):[0-5]\d$/', $out[ $t ] ) ) {
				$out[ $t ] = $d[ $t ];
			}
		}
		if ( $out['report_email'] ) {
			$emails = array_filter( array_map( 'sanitize_email', preg_split( '/[\s,;]+/', $out['report_email'] ) ) );
			$out['report_email'] = implode( ', ', $emails );
		}
		$out['instant_min_severity'] = in_array( $out['instant_min_severity'], array( 'critical', 'high' ), true ) ? $out['instant_min_severity'] : 'critical';
		$out['instant_max_per_hour'] = min( 50, max( 1, $out['instant_max_per_hour'] ) );
		$out['integrity_batch']      = min( 3000, max( 50, $out['integrity_batch'] ) );
		$out['retention_days']       = min( 365, max( 7, $out['retention_days'] ) );
		$out['learning_hours']       = min( 168, $out['learning_hours'] );
		return $out;
	}

	/** True during the first N hours after install: new baselines are recorded silently. */
	public static function in_learning() {
		$installed = (int) get_option( 'nightward_installed_at', 0 );
		return $installed && ( time() - $installed ) < HOUR_IN_SECONDS * (int) self::get( 'learning_hours', 24 );
	}
}
