<?php
/**
 * Custom tables. Kept deliberately simple: no ON DUPLICATE KEY, no JSON functions —
 * works on MySQL, MariaDB and the SQLite drop-in.
 */

namespace Nightward;

defined( 'ABSPATH' ) || exit;

class DB {

	public static function events() {
		global $wpdb;
		return $wpdb->prefix . 'nightward_events';
	}

	public static function egress() {
		global $wpdb;
		return $wpdb->prefix . 'nightward_egress';
	}

	public static function files() {
		global $wpdb;
		return $wpdb->prefix . 'nightward_files';
	}

	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$c = $wpdb->get_charset_collate();

		dbDelta( 'CREATE TABLE ' . self::events() . " (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			fingerprint char(40) NOT NULL,
			module varchar(32) NOT NULL,
			type varchar(64) NOT NULL,
			severity varchar(10) NOT NULL,
			title varchar(255) NOT NULL,
			details longtext NULL,
			component varchar(191) NOT NULL DEFAULT '',
			file varchar(255) NOT NULL DEFAULT '',
			line int(11) NOT NULL DEFAULT 0,
			hits int(11) NOT NULL DEFAULT 1,
			status varchar(12) NOT NULL DEFAULT 'open',
			alerted tinyint(1) NOT NULL DEFAULT 0,
			first_seen datetime NOT NULL,
			last_seen datetime NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY fingerprint (fingerprint),
			KEY sev_seen (severity,last_seen),
			KEY status (status)
		) $c;" );

		dbDelta( 'CREATE TABLE ' . self::egress() . " (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			host varchar(191) NOT NULL,
			component varchar(191) NOT NULL,
			sample_url varchar(300) NOT NULL DEFAULT '',
			hits int(11) NOT NULL DEFAULT 0,
			intercepted int(11) NOT NULL DEFAULT 0,
			errors int(11) NOT NULL DEFAULT 0,
			first_seen datetime NOT NULL,
			last_seen datetime NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY host_component (host,component),
			KEY last_seen (last_seen)
		) $c;" );

		dbDelta( 'CREATE TABLE ' . self::files() . " (
			path_key char(40) NOT NULL,
			path varchar(512) NOT NULL,
			package varchar(191) NOT NULL,
			hash char(64) NOT NULL,
			size bigint(20) NOT NULL DEFAULT 0,
			source varchar(10) NOT NULL DEFAULT 'tofu',
			seen_at datetime NOT NULL,
			PRIMARY KEY  (path_key),
			KEY package (package)
		) $c;" );

		update_option( 'nightward_db_version', NIGHTWARD_DB_VERSION, false );
	}

	public static function drop() {
		global $wpdb;
		foreach ( array( self::events(), self::egress(), self::files() ) as $t ) {
			$wpdb->query( "DROP TABLE IF EXISTS {$t}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		}
	}

	public static function ready() {
		static $ready = false;
		if ( ! $ready ) {
			$ready = get_option( 'nightward_db_version' ) === NIGHTWARD_DB_VERSION;
		}
		return $ready;
	}
}
