<?php
/**
 * Constants and class loading. Safe to include from the early MU loader and from the main plugin file.
 */

defined( 'ABSPATH' ) || exit;

if ( ! defined( 'NIGHTWARD_VERSION' ) ) {
	define( 'NIGHTWARD_VERSION', '1.1.4' );
}
if ( ! defined( 'NIGHTWARD_FILE' ) ) {
	define( 'NIGHTWARD_FILE', dirname( __DIR__ ) . '/nightward.php' );
}
if ( ! defined( 'NIGHTWARD_DIR' ) ) {
	define( 'NIGHTWARD_DIR', trailingslashit( dirname( __DIR__ ) ) );
}
if ( ! defined( 'NIGHTWARD_DB_VERSION' ) ) {
	define( 'NIGHTWARD_DB_VERSION', '1' );
}

$nightward_files = array(
	'class-util.php',
	'class-settings.php',
	'class-db.php',
	'class-attribution.php',
	'class-events.php',
	'class-installer.php',
	'class-cron.php',
	'class-reports.php',
	'class-export.php',
	'monitor/class-outbound.php',
	'monitor/class-hooks-watch.php',
	'monitor/class-privilege-guard.php',
	'monitor/class-options-watch.php',
	'monitor/class-cron-guard.php',
	'scanner/class-integrity.php',
	'scanner/class-upload-guard.php',
	'scanner/class-update-channel.php',
	'scanner/class-hardening.php',
	'class-plugin.php',
);
foreach ( $nightward_files as $nightward_f ) {
	require_once __DIR__ . '/' . $nightward_f;
}
unset( $nightward_files, $nightward_f );
