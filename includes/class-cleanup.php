<?php
/**
 * Findings of a plugin or theme that has been deleted disappear with it, unless
 * something it did is still on the site: an administrator it created, a
 * scheduled task it left, a file in uploads (those keep their own events and
 * close only when the trace itself is gone).
 */

namespace Nightward;

defined( 'ABSPATH' ) || exit;

class Cleanup {

	/** Findings that exist only while the code is installed. */
	const CODE_MODULES = array( 'outbound', 'interception', 'hooks', 'integrity', 'update_channel', 'options' );

	public static function init() {
		add_action( 'deleted_plugin', array( __CLASS__, 'on_deleted_plugin' ), 10, 2 );
		add_action( 'deleted_theme', array( __CLASS__, 'on_deleted_theme' ), 10, 2 );
		// Removed by FTP, WP-CLI or a deploy: noticed when the Plugins or Themes screen opens.
		add_action( 'load-plugins.php', array( __CLASS__, 'sweep' ) );
		add_action( 'load-themes.php', array( __CLASS__, 'sweep' ) );
	}

	public static function on_deleted_plugin( $plugin_file, $deleted ) {
		if ( $deleted ) {
			$slug = false !== strpos( $plugin_file, '/' ) ? dirname( $plugin_file ) : preg_replace( '/\.php$/', '', $plugin_file );
			self::forget( 'plugin:' . $slug );
		}
	}

	public static function on_deleted_theme( $stylesheet, $deleted ) {
		if ( $deleted ) {
			self::forget( 'theme:' . $stylesheet );
		}
	}

	/** Is the plugin or theme still on disk? */
	public static function exists( $component ) {
		if ( 0 === strpos( $component, 'plugin:' ) ) {
			$slug = substr( $component, 7 );
			return '' === $slug || is_dir( WP_PLUGIN_DIR . '/' . $slug ) || is_file( WP_PLUGIN_DIR . '/' . $slug . '.php' );
		}
		if ( 0 === strpos( $component, 'theme:' ) ) {
			$slug = substr( $component, 6 );
			return '' === $slug || is_dir( get_theme_root( $slug ) . '/' . $slug );
		}
		return true; // core, mu, drop-ins: not handled here
	}

	/** Daily: packages removed outside the dashboard (FTP, file manager, deploy). */
	public static function sweep() {
		global $wpdb;
		if ( ! DB::ready() ) {
			return 0;
		}
		$like  = array( 'plugin:%', 'theme:%' );
		$comps = array_merge(
			(array) $wpdb->get_col( $wpdb->prepare( 'SELECT DISTINCT component FROM ' . DB::events() . ' WHERE component LIKE %s OR component LIKE %s', $like[0], $like[1] ) ), // phpcs:ignore
			(array) $wpdb->get_col( $wpdb->prepare( 'SELECT DISTINCT component FROM ' . DB::egress() . ' WHERE component LIKE %s OR component LIKE %s', $like[0], $like[1] ) ), // phpcs:ignore
			(array) $wpdb->get_col( $wpdb->prepare( 'SELECT DISTINCT package FROM ' . DB::files() . ' WHERE package LIKE %s OR package LIKE %s', $like[0], $like[1] ) ) // phpcs:ignore
		);
		$n = 0;
		foreach ( array_unique( $comps ) as $c ) {
			$n += self::forget( $c );
		}
		return $n;
	}

	/**
	 * Delete what is left of a removed package.
	 *
	 * @return int events deleted
	 */
	public static function forget( $component ) {
		global $wpdb;
		$component = (string) $component;
		if ( '' === $component || self::exists( $component ) || ! DB::ready() ) {
			return 0;
		}
		$t    = DB::events();
		$ids  = array();
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, module, details FROM {$t} WHERE component = %s", $component ) ); // phpcs:ignore
		$cron = function_exists( '_get_cron_array' ) ? (array) _get_cron_array() : array();
		$live = array();
		foreach ( $cron as $hooks ) {
			foreach ( (array) $hooks as $hook => $unused ) {
				$live[ $hook ] = true;
			}
		}
		foreach ( $rows as $r ) {
			$d = json_decode( (string) $r->details, true );
			$d = is_array( $d ) ? $d : array();
			if ( in_array( $r->module, self::CODE_MODULES, true ) ) {
				$ids[] = (int) $r->id;
			} elseif ( 'cron' === $r->module ) {
				// The task it scheduled is gone too - otherwise it is a trace worth keeping.
				if ( empty( $d['hook'] ) || ! isset( $live[ $d['hook'] ] ) ) {
					$ids[] = (int) $r->id;
				}
			} elseif ( 'privilege' === $r->module ) {
				// An administrator it created or changed is still there: keep.
				$uid = isset( $d['user_id'] ) ? (int) $d['user_id'] : 0;
				if ( ! $uid || ! user_can( $uid, 'manage_options' ) ) {
					$ids[] = (int) $r->id;
				}
			}
		}
		foreach ( array_chunk( $ids, 200 ) as $chunk ) {
			$wpdb->query( "DELETE FROM {$t} WHERE id IN (" . implode( ',', array_map( 'intval', $chunk ) ) . ')' ); // phpcs:ignore
		}
		$wpdb->delete( DB::egress(), array( 'component' => $component ) );
		$wpdb->delete( DB::files(), array( 'package' => $component ) );

		$versions = (array) get_option( 'nightward_integrity_versions', array() );
		if ( isset( $versions[ $component ] ) ) {
			unset( $versions[ $component ] );
			update_option( 'nightward_integrity_versions', $versions, false );
		}
		// Interception history is keyed by "file:line" of the callback.
		$prefix = ( 0 === strpos( $component, 'theme:' ) ? 'wp-content/themes/' : 'wp-content/plugins/' ) . substr( $component, strpos( $component, ':' ) + 1 );
		$seen   = (array) get_option( 'nightward_intercept_hosts', array() );
		$kept   = array_filter( $seen, function ( $k ) use ( $prefix ) {
			return 0 !== strpos( (string) $k, $prefix . '/' ) && 0 !== strpos( (string) $k, $prefix . '.php' );
		}, ARRAY_FILTER_USE_KEY );
		if ( count( $kept ) !== count( $seen ) ) {
			update_option( 'nightward_intercept_hosts', $kept, false );
		}

		if ( $ids ) {
			$kind = 0 === strpos( $component, 'theme:' ) ? 'theme' : 'plugin';
			Events::record( array(
				'module'   => 'system',
				'type'     => 'package_removed',
				'severity' => 'info',
				/* translators: 1: plugin or theme slug, 2: number of findings */
				'title'    => array( 'theme' === $kind ? __( 'Theme %1$s was removed, findings cleared: %2$d', 'nightward' ) : __( 'Plugin %1$s was removed, findings cleared: %2$d', 'nightward' ), substr( $component, strpos( $component, ':' ) + 1 ), count( $ids ) ),
				'details'  => array(
					'explanation' => __( 'Findings that existed only while its code was installed (requests, hooks, file changes, update channel) were deleted. Administrators, scheduled tasks and files it left behind keep their findings until they are gone too.', 'nightward' ),
				),
				'key'      => 'system|package_removed|' . $component,
			) );
			Events::flush();
		}
		return count( $ids );
	}
}
