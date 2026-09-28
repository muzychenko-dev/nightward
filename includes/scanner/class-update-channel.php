<?php
/**
 * Update Channel.
 *
 * Checks WHERE plugin and theme updates come from. A WordPress.org plugin
 * whose update suddenly points to another server, or a premium plugin that
 * downloads its "update" from a host unrelated to its vendor, is how pirated
 * copies and hijacked update servers deliver payloads.
 *
 * - Offered updates (the update transient) are checked hourly, before anyone
 *   clicks "Update".
 * - Actual downloads are checked at upgrader_pre_download and, when enabled,
 *   blocked.
 */

namespace Nightward\Scanner;

use Nightward\Attribution;
use Nightward\Events;
use Nightward\Settings;
use Nightward\Util;

defined( 'ABSPATH' ) || exit;

class Update_Channel {

	public static function init() {
		add_filter( 'upgrader_pre_download', array( __CLASS__, 'pre_download' ), PHP_INT_MAX, 4 );
	}

	/** Hosts that legitimately serve packages for many vendors. */
	public static function neutral_hosts() {
		return array( 'wordpress.org', 'w.org', 'github.com', 'githubusercontent.com', 'codeload.github.com', 'gitlab.com', 'bitbucket.org',
			'amazonaws.com', 'cloudfront.net', 'freemius.com', 'envato.com', 'envatousercontent.com', 'woocommerce.com', 'woo.com',
			'wpengine.com', 'digitaloceanspaces.com', 'backblazeb2.com', 'googleapis.com', 'r2.dev', 'cloudflarestorage.com', 'kinsta.cloud' );
	}

	/**
	 * @return array( verdict: ok|foreign|bad|hijack|insecure, reason )
	 */
	public static function assess( $component, $package_url, $is_wporg ) {
		$host = Util::host_of( $package_url );
		if ( ! $host ) {
			return array( 'ok', '' ); // локальний zip
		}
		$reg = Util::registrable( $host );
		$bad = Util::bad_host_reason( $host );
		if ( $bad ) {
			return array( 'bad', $bad );
		}
		if ( $is_wporg && 'downloads.wordpress.org' !== $host ) {
			return array( 'hijack', __( 'the plugin is from WordPress.org, but the update is served by another server', 'nightward' ) );
		}
		if ( 0 === stripos( $package_url, 'http://' ) ) {
			return array( 'insecure', __( 'package is downloaded over plain HTTP and can be replaced in transit', 'nightward' ) );
		}
		if ( Util::is_public_ip_literal( $host ) ) {
			return array( 'foreign', __( 'package is downloaded from a bare IP address', 'nightward' ) );
		}
		$vendor  = Attribution::vendor_domains( $component );
		$trusted = Settings::trusted_hosts();
		if ( in_array( $reg, $vendor, true ) || in_array( $reg, self::neutral_hosts(), true ) || in_array( $host, $trusted, true ) || in_array( $reg, $trusted, true ) || Util::is_own_host( $host ) ) {
			return array( 'ok', '' );
		}
		return array( 'foreign', $vendor
			/* translators: %s: vendor domains */
			? sprintf( __( 'host is unrelated to the vendor (%s)', 'nightward' ), implode( ', ', $vendor ) )
			: __( 'the plugin declares no vendor website, so the source cannot be matched', 'nightward' ) );
	}

	private static function severity( $verdict ) {
		$m = array( 'bad' => 'critical', 'hijack' => 'critical', 'insecure' => 'medium', 'foreign' => 'medium' );
		return isset( $m[ $verdict ] ) ? $m[ $verdict ] : 'info';
	}

	public static function pre_download( $reply, $package, $upgrader = null, $extra = array() ) {
		if ( false !== $reply || ! is_string( $package ) ) {
			return $reply;
		}
		$component = '';
		if ( ! empty( $extra['plugin'] ) ) {
			$p         = $extra['plugin'];
			$component = 'plugin:' . ( false === strpos( $p, '/' ) ? preg_replace( '/\.php$/', '', $p ) : strtok( $p, '/' ) );
		} elseif ( ! empty( $extra['theme'] ) ) {
			$component = 'theme:' . $extra['theme'];
		} elseif ( isset( $extra['type'] ) && 'core' === $extra['type'] ) {
			$component = 'core';
		}
		$is_wporg = self::is_wporg_item( $component );
		if ( 'core' === $component ) {
			$is_wporg = true;
		}
		list( $verdict, $why ) = self::assess( $component, $package, $is_wporg );
		if ( 'ok' === $verdict ) {
			return $reply;
		}
		$block = in_array( $verdict, array( 'bad', 'hijack' ), true ) || ( Settings::get( 'block_foreign_packages', 0 ) && 'foreign' === $verdict );
		Events::record( array(
			'module'    => 'update_channel',
			'type'      => 'download_' . $verdict,
			'severity'  => $block ? 'critical' : self::severity( $verdict ),
			/* translators: 1: plugin name, 2: host */
			'title'     => array( $block ? __( 'Blocked update of %1$s from %2$s', 'nightward' ) : __( 'Update of %1$s downloaded from %2$s', 'nightward' ), $component ? Attribution::label( $component ) : '?', Util::host_of( $package ) ),
			'details'   => array(
				/* translators: %s: reason */
				'explanation' => array( __( 'Reason: %s.', 'nightward' ), $why ),
				'package'     => Util::redact_url( $package ),
				'blocked'     => $block,
				'hint'        => __( 'If this source is legitimate, add its domain to Trusted hosts in Settings.', 'nightward' ),
			),
			'component' => $component,
			'key'       => 'upd|dl|' . $component . '|' . Util::host_of( $package ),
		) );
		if ( $block ) {
			/* translators: %s: reason */
			return new \WP_Error( 'nightward_blocked_package', sprintf( __( 'Nightward blocked this download: %s.', 'nightward' ), $why ) );
		}
		return $reply;
	}

	/** Is this plugin a WordPress.org plugin according to the update API itself? */
	private static function is_wporg_item( $component ) {
		if ( 0 !== strpos( $component, 'plugin:' ) ) {
			return false;
		}
		$data = Attribution::plugin_data( $component );
		if ( ! $data ) {
			return false;
		}
		$t = get_site_transient( 'update_plugins' );
		foreach ( array( 'response', 'no_update' ) as $bucket ) {
			if ( isset( $t->{$bucket}[ $data['_file'] ] ) ) {
				$item = $t->{$bucket}[ $data['_file'] ];
				$id   = is_object( $item ) ? ( isset( $item->id ) ? $item->id : '' ) : ( isset( $item['id'] ) ? $item['id'] : '' );
				return 0 === strpos( (string) $id, 'w.org/' );
			}
		}
		return false;
	}

	/** Hourly: look at updates that are waiting to be installed. */
	public static function check_offered_updates() {
		$t = get_site_transient( 'update_plugins' );
		self::check_malformed( $t );
		if ( ! empty( $t->response ) ) {
			foreach ( (array) $t->response as $file => $item ) {
				$item      = (object) $item;
				$package   = isset( $item->package ) ? (string) $item->package : '';
				$component = 'plugin:' . ( false === strpos( $file, '/' ) ? preg_replace( '/\.php$/', '', $file ) : strtok( $file, '/' ) );
				$is_wporg  = isset( $item->id ) && 0 === strpos( (string) $item->id, 'w.org/' );
				if ( ! $package ) {
					continue;
				}
				list( $verdict, $why ) = self::assess( $component, $package, $is_wporg );
				if ( 'ok' === $verdict ) {
					continue;
				}
				// Для офіційних плагінів — перевіряємо також, хто підмінив запис.
				Events::record( array(
					'module'    => 'update_channel',
					'type'      => 'offered_' . $verdict,
					'severity'  => self::severity( $verdict ),
					/* translators: 1: plugin name, 2: version, 3: host */
					'title'     => array( __( 'Pending update %1$s %2$s comes from %3$s', 'nightward' ), Attribution::label( $component ), isset( $item->new_version ) ? $item->new_version : '', Util::host_of( $package ) ),
					'details'   => array(
						/* translators: %s: reason */
				'explanation' => array( __( 'Reason: %s.', 'nightward' ), $why ),
						'package'     => Util::redact_url( $package ),
						'advice'      => 'bad' === $verdict || 'hijack' === $verdict
							? __( 'Do not install this update. Find the plugin/theme code that injects it (see Sensitive hooks: pre_set_site_transient_update_plugins).', 'nightward' )
							: __( 'Verify that the vendor really distributes updates from this host before updating.', 'nightward' ),
						'injectors'   => self::injectors(),
					),
					'component' => $component,
					'key'       => 'upd|offer|' . $component . '|' . Util::host_of( $package ),
				) );
			}
		}
		$tt = get_site_transient( 'update_themes' );
		if ( ! empty( $tt->response ) ) {
			foreach ( (array) $tt->response as $slug => $item ) {
				$item    = (array) $item;
				$package = isset( $item['package'] ) ? (string) $item['package'] : '';
				if ( ! $package ) {
					continue;
				}
				$is_wporg = 'downloads.wordpress.org' === Util::host_of( isset( $item['url'] ) ? str_replace( 'wordpress.org/themes', 'downloads.wordpress.org/themes', $item['url'] ) : '' );
				list( $verdict, $why ) = self::assess( 'theme:' . $slug, $package, false );
				if ( 'ok' === $verdict ) {
					continue;
				}
				Events::record( array(
					'module'    => 'update_channel',
					'type'      => 'offered_' . $verdict,
					'severity'  => self::severity( $verdict ),
					/* translators: 1: theme name, 2: host */
					'title'     => array( __( 'Pending theme update %1$s comes from %2$s', 'nightward' ), Attribution::label( 'theme:' . $slug ), Util::host_of( $package ) ),
					'details'   => array( /* translators: %s: reason */
				'explanation' => array( __( 'Reason: %s.', 'nightward' ), $why ), 'package' => Util::redact_url( $package ), 'wporg_listing' => $is_wporg ),
					'component' => 'theme:' . $slug,
					'key'       => 'upd|offer|theme:' . $slug . '|' . Util::host_of( $package ),
				) );
			}
		}
	}

	/** Non-core callbacks that can rewrite the update list. */
	public static function injectors() {
		global $wp_filter;
		$out = array();
		foreach ( array( 'pre_set_site_transient_update_plugins', 'site_transient_update_plugins' ) as $hook ) {
			if ( empty( $wp_filter[ $hook ] ) ) {
				continue;
			}
			foreach ( $wp_filter[ $hook ]->callbacks as $cbs ) {
				foreach ( $cbs as $cb ) {
					$i = Attribution::callback_info( $cb['function'] );
					if ( ! in_array( $i['component'], array( 'core', 'nightward' ), true ) ) {
						$out[] = $hook . ': ' . $i['name'] . ' — ' . $i['file'] . ':' . $i['line'];
					}
				}
			}
		}
		return array_slice( array_unique( $out ), 0, 15 );
	}

	/**
	 * Entries without the "plugin" field are never written by WordPress.org; they come
	 * from custom updaters (often in pirated copies) and break Plugins → Add New with
	 * "Undefined property: stdClass::$plugin".
	 */
	private static function check_malformed( $t ) {
		if ( ! is_object( $t ) ) {
			return;
		}
		$bad = array();
		foreach ( array( 'response', 'no_update' ) as $bucket ) {
			if ( empty( $t->{$bucket} ) ) {
				continue;
			}
			foreach ( (array) $t->{$bucket} as $file => $item ) {
				if ( is_object( $item ) && empty( $item->plugin ) ) {
					$bad[] = $file;
				}
			}
		}
		if ( ! $bad ) {
			return;
		}
		Events::record( array(
			'module'   => 'update_channel',
			'type'     => 'malformed_update_data',
			'severity' => 'medium',
			/* translators: %s: plugin files */
			'title'    => array( __( 'Update data injected without the required "plugin" field: %s', 'nightward' ), implode( ', ', array_slice( $bad, 0, 5 ) ) ),
			'details'  => array(
				'explanation' => __( 'A custom updater wrote its own entry into the WordPress update list. WordPress.org never produces such entries; they cause the "Undefined property: stdClass::$plugin" warning on Plugins → Add New. Check the code listed below.', 'nightward' ),
				'files'       => $bad,
				'injectors'   => self::injectors(),
			),
			'key'      => 'upd|malformed|' . implode( ',', $bad ),
		) );
	}
}
