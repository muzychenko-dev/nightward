<?php
/**
 * Wiring. boot('mu') runs from the early loader, boot('plugin') from the main
 * file; runtime monitors start once, admin UI is added in plugin mode.
 */

namespace Nightward;

defined( 'ABSPATH' ) || exit;

final class Plugin {

	private static $instance = null;
	private $monitors_started = false;
	private $late_started     = false;
	public $boot_mode         = '';

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function boot( $mode ) {
		if ( ! $this->monitors_started ) {
			$this->monitors_started = true;
			$this->boot_mode        = $mode;
			$this->start_monitors();
		}
		if ( 'plugin' === $mode && ! $this->late_started ) {
			$this->late_started = true;
			$this->start_late();
		}
	}

	private function start_monitors() {
		if ( Settings::enabled( 'outbound' ) ) {
			Monitor\Outbound::init();
		}
		if ( Settings::enabled( 'privilege' ) ) {
			Monitor\Privilege_Guard::init();
		}
		if ( Settings::enabled( 'options' ) ) {
			Monitor\Options_Watch::init();
		}
		if ( Settings::enabled( 'hooks' ) ) {
			Monitor\Hooks_Watch::init();
		}
		if ( Settings::enabled( 'update_channel' ) ) {
			Scanner\Update_Channel::init();
		}
		Scanner\Integrity::init_hooks();
		Cron::init();
	}

	private function start_late() {
		add_action( 'init', array( $this, 'load_textdomain' ), 1 );
		add_action( 'plugins_loaded', array( $this, 'maybe_upgrade' ) );
		if ( is_admin() ) {
			require_once NIGHTWARD_DIR . 'admin/class-admin.php';
			Admin\Admin::init();
		}
		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( '\WP_CLI' ) ) {
			require_once NIGHTWARD_DIR . 'includes/class-cli.php';
			\WP_CLI::add_command( 'nightward', 'Nightward\\CLI' );
		}
	}

	public function load_textdomain() {
		load_plugin_textdomain( 'nightward', false, dirname( plugin_basename( NIGHTWARD_FILE ) ) . '/languages' );
	}

	public function maybe_upgrade() {
		if ( get_option( 'nightward_db_version' ) !== NIGHTWARD_DB_VERSION ) {
			DB::install();
		}
		// Loader should follow the setting and the plugin location.
		if ( Settings::get( 'mu_loader', 1 ) && ! Installer::loader_installed() && is_writable( dirname( WPMU_PLUGIN_DIR ) ) && get_transient( 'nightward_loader_retry' ) === false ) {
			set_transient( 'nightward_loader_retry', 1, DAY_IN_SECONDS );
			Installer::install_loader();
		}
	}

	public static function url( $path = '' ) {
		return plugins_url( $path, NIGHTWARD_FILE );
	}
}
