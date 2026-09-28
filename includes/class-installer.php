<?php
/**
 * Activation, deactivation and the early MU loader.
 */

namespace Nightward;

defined( 'ABSPATH' ) || exit;

class Installer {

	const LOADER = '0-nightward-early.php';

	public static function activate() {
		DB::install();
		if ( ! get_option( 'nightward_installed_at' ) ) {
			add_option( 'nightward_installed_at', time(), '', false );
		}
		if ( false === get_option( Settings::OPTION, false ) ) {
			add_option( Settings::OPTION, Settings::defaults(), '', true );
		}
		if ( Settings::get( 'mu_loader', 1 ) ) {
			self::install_loader();
		}
		Cron::schedule_all();
		Events::record( array(
			'module'   => 'system',
			'type'     => 'activated',
			'severity' => 'info',
			'title'    => __( 'Nightward activated. Baselines for hooks, outbound hosts and scheduled tasks are being learned.', 'nightward' ),
			'key'      => 'system|activated|' . time(),
		) );
		Events::flush();
		// Перший скан цілісності — одразу, а не о 03:30: знімок «як є зараз» і є еталоном.
		wp_schedule_single_event( time() + 60, 'nightward_integrity_start' );
	}

	public static function deactivate() {
		self::remove_loader();
		Cron::unschedule_all();
	}

	public static function loader_path() {
		return trailingslashit( WPMU_PLUGIN_DIR ) . self::LOADER;
	}

	public static function loader_installed() {
		return is_file( self::loader_path() );
	}

	public static function install_loader() {
		$dir = WPMU_PLUGIN_DIR;
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return new \WP_Error( 'nightward_mu', __( 'Cannot create the mu-plugins directory.', 'nightward' ) );
		}
		$main     = wp_normalize_path( NIGHTWARD_FILE );
		$basename = plugin_basename( NIGHTWARD_FILE );
		$code     = "<?php\n/**\n * Plugin Name: Nightward Early Loader\n"
			. " * Description: Starts Nightward monitors before other plugins load, so their hooks and requests are seen from the first line. Created and removed by Nightward automatically.\n"
			. " * Version: " . NIGHTWARD_VERSION . "\n */\n\n"
			. "defined( 'ABSPATH' ) || exit;\n\n"
			. '$nightward_main = ' . var_export( $main, true ) . ";\n"
			. '$nightward_base = ' . var_export( $basename, true ) . ";\n"
			. "\$nightward_active = in_array( \$nightward_base, (array) get_option( 'active_plugins', array() ), true )\n"
			. "\t|| ( is_multisite() && array_key_exists( \$nightward_base, (array) get_site_option( 'active_sitewide_plugins', array() ) ) );\n"
			. "if ( \$nightward_active && is_file( \$nightward_main ) && ! defined( 'NIGHTWARD_VERSION' ) ) {\n"
			. "\tdefine( 'NIGHTWARD_FILE', \$nightward_main );\n"
			. "\trequire_once dirname( \$nightward_main ) . '/includes/bootstrap.php';\n"
			. "\tNightward\\Plugin::instance()->boot( 'mu' );\n"
			. "}\n"
			. "unset( \$nightward_main, \$nightward_base, \$nightward_active );\n";
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( false === @file_put_contents( self::loader_path(), $code ) ) {
			return new \WP_Error( 'nightward_mu', __( 'mu-plugins is not writable; Nightward will start later than other plugins.', 'nightward' ) );
		}
		// Власний файл не має підняти тривогу в Upload Guard.
		update_option( 'nightward_mu_known', array_unique( array_merge( (array) get_option( 'nightward_mu_known', array() ), array( self::LOADER ) ) ), false );
		return true;
	}

	public static function remove_loader() {
		if ( self::loader_installed() ) {
			wp_delete_file( self::loader_path() );
		}
	}
}
