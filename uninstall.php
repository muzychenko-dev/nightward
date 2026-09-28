<?php
/**
 * Removes everything Nightward stored: tables, options, user meta, the MU loader.
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

foreach ( array( 'nightward_events', 'nightward_egress', 'nightward_files' ) as $t ) {
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}{$t}" ); // phpcs:ignore
}
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'nightward\\_%' OR option_name LIKE '\\_transient\\_nightward\\_%' OR option_name LIKE '\\_transient\\_timeout\\_nightward\\_%'" ); // phpcs:ignore
$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key = 'nightward_known_nets'" ); // phpcs:ignore

$loader = trailingslashit( WPMU_PLUGIN_DIR ) . '0-nightward-early.php';
if ( is_file( $loader ) ) {
	wp_delete_file( $loader );
}
foreach ( array( 'nightward_daily_report', 'nightward_hourly', 'nightward_daily_maintenance', 'nightward_integrity_start', 'nightward_integrity_step', 'nightward_instant_retry' ) as $h ) {
	wp_clear_scheduled_hook( $h );
}
