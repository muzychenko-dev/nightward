<?php
/**
 * Options Watch.
 *
 * 1. Sensitive options: site URL, admin e-mail, default role, registration,
 *    active plugins, active theme — changed outside Settings screens → alert.
 * 2. Write-on-every-request: a sample of requests records which options are
 *    written during page views. A plugin that writes the database on every
 *    visit slows the site and is often a sign of a licence "phone home" loop.
 * 3. Autoload weight: the options WordPress loads on every request.
 */

namespace Nightward\Monitor;

use Nightward\Attribution;
use Nightward\Events;
use Nightward\Settings;
use Nightward\Util;

defined( 'ABSPATH' ) || exit;

class Options_Watch {

	const STATS      = 'nightward_option_writes';
	const SAMPLE_ONE = 20;

	private static $writes  = array();
	private static $sampled = null;

	public static function sensitive() {
		return array( 'siteurl', 'home', 'admin_email', 'default_role', 'users_can_register', 'active_plugins', 'template', 'stylesheet', self::roles_option() );
	}

	public static function roles_option() {
		global $wpdb;
		return $wpdb->get_blog_prefix() . 'user_roles';
	}

	public static function init() {
		add_action( 'updated_option', array( __CLASS__, 'on_update' ), PHP_INT_MAX, 3 );
		add_action( 'added_option', array( __CLASS__, 'on_add' ), PHP_INT_MAX, 2 );
		add_action( 'update_site_option_active_sitewide_plugins', array( __CLASS__, 'on_network_plugins' ), PHP_INT_MAX, 3 );
		add_action( 'shutdown', array( __CLASS__, 'persist' ), 20 );
	}

	private static function sampled() {
		if ( null === self::$sampled ) {
			self::$sampled = ! is_admin() && ! wp_doing_cron() && ! ( defined( 'WP_CLI' ) && WP_CLI ) && 0 === wp_rand( 0, self::SAMPLE_ONE - 1 );
		}
		return self::$sampled;
	}

	public static function on_add( $option, $value ) {
		self::track( $option );
		if ( in_array( $option, self::sensitive(), true ) ) {
			self::on_update( $option, null, $value );
		}
	}

	public static function on_update( $option, $old, $value ) {
		if ( 0 !== strpos( $option, 'nightward_' ) ) {
			self::track( $option );
		}
		if ( ! in_array( $option, self::sensitive(), true ) ) {
			return;
		}
		$c        = Attribution::caller();
		$ctx      = Util::request_context();
		$by_admin = 'core' === $c['component'] && current_user_can( 'manage_options' ) && in_array( $ctx, array( 'admin', 'rest', 'ajax' ), true );
		$cli      = 'cli' === $ctx;

		switch ( true ) {
			case in_array( $option, array( 'siteurl', 'home' ), true ):
				$sev = $by_admin || $cli ? 'medium' : 'critical';
				$why = __( 'Changing the site address redirects all visitors and logins. Done outside Settings → General, this is how sites get hijacked to spam or phishing domains.', 'nightward' );
				break;
			case 'admin_email' === $option:
				$sev = $by_admin || $cli ? 'info' : 'high';
				$why = __( 'Whoever owns the admin e-mail receives password resets and security notices.', 'nightward' );
				break;
			case 'default_role' === $option:
				$sev = in_array( $value, array( 'administrator', 'editor', 'shop_manager' ), true ) ? 'critical' : ( $by_admin ? 'info' : 'medium' );
				/* translators: %s: role */
				$why = array( __( 'New registrations will now get the role "%s".', 'nightward' ), $value );
				break;
			case 'users_can_register' === $option:
				$sev = $value ? ( $by_admin ? 'low' : 'high' ) : 'info';
				$why = $value ? __( 'Anyone can now register an account.', 'nightward' ) : __( 'Registration disabled.', 'nightward' );
				if ( $value && in_array( get_option( 'default_role' ), array( 'administrator', 'editor', 'shop_manager' ), true ) ) {
					$sev = 'critical';
				}
				break;
			case 'active_plugins' === $option:
				self::plugins_changed( (array) $old, (array) $value, $c, $ctx );
				return;
			case in_array( $option, array( 'template', 'stylesheet' ), true ):
				$sev = $by_admin || $cli ? 'info' : 'high';
				$why = __( 'The active theme was switched.', 'nightward' );
				break;
			default: // wp_user_roles
				self::roles_changed( (array) $old, (array) $value, $c, $by_admin );
				return;
		}
		if ( 'info' === $sev && $by_admin ) {
			return; // звичайна робота в налаштуваннях — не засмічуємо журнал
		}
		Events::record( array(
			'module'    => 'options',
			'type'      => 'sensitive_option',
			'severity'  => $sev,
			/* translators: 1: option name, 2: plugin name */
			'title'     => array( __( 'Option %1$s changed by %2$s', 'nightward' ), $option, Attribution::label( $c['component'] ) ),
			'details'   => array(
				'explanation' => $why,
				'old'         => is_scalar( $old ) ? (string) $old : wp_json_encode( $old ),
				'new'         => is_scalar( $value ) ? (string) $value : wp_json_encode( $value ),
				'context'     => $ctx,
				'request'     => Util::request_path(),
				'ip'          => Util::client_ip(),
			),
			'component' => $c['component'],
			'file'      => $c['file'],
			'line'      => $c['line'],
			'key'       => 'options|' . $option . '|' . md5( maybe_serialize( $value ) ),
		) );
	}

	private static function plugins_changed( array $old, array $new, array $c, $ctx ) {
		$added = array_diff( $new, $old );
		if ( ! $added ) {
			return;
		}
		$ui = 'cli' === $ctx || ( 'core' === $c['component'] && current_user_can( 'activate_plugins' ) && in_array( $ctx, array( 'admin', 'ajax', 'rest' ), true ) );
		// Nightward itself; the SQLite drop-in re-registers its own plugin.
		$added = array_filter( $added, function ( $p ) use ( $c ) {
			return 0 !== strpos( $p, 'nightward/' ) && ! ( 'dropin:db.php' === $c['component'] && 0 === strpos( $p, 'sqlite-database-integration/' ) );
		} );
		if ( ! $added ) {
			return;
		}
		Hooks_Watch::mark_relearn( array_map( function ( $p ) {
			return 'plugin:' . ( false === strpos( $p, '/' ) ? preg_replace( '/\.php$/', '', $p ) : strtok( $p, '/' ) );
		}, $added ) );
		if ( $ui ) {
			return;
		}
		Events::record( array(
			'module'    => 'options',
			'type'      => 'plugin_activated_by_code',
			'severity'  => 'high',
			/* translators: 1: plugin file(s), 2: plugin name */
			'title'     => array( __( 'Plugin activated by code: %1$s (by %2$s)', 'nightward' ), implode( ', ', $added ), Attribution::label( $c['component'] ) ),
			'details'   => array(
				'explanation' => __( 'A plugin was activated without an administrator using the Plugins screen. Droppers use this to switch on a second-stage payload.', 'nightward' ),
				'context'     => $ctx,
				'request'     => Util::request_path(),
			),
			'component' => $c['component'],
			'file'      => $c['file'],
			'line'      => $c['line'],
			'key'       => 'options|activate|' . implode( ',', $added ),
		) );
	}

	/** A role gaining admin-grade capabilities outside the admin. */
	private static function roles_changed( array $old, array $new, array $c, $by_admin ) {
		$danger = array( 'manage_options', 'edit_users', 'promote_users', 'create_users', 'install_plugins', 'activate_plugins', 'edit_plugins', 'unfiltered_html', 'edit_files', 'update_core' );
		foreach ( $new as $role => $def ) {
			if ( 'administrator' === $role || empty( $def['capabilities'] ) ) {
				continue;
			}
			$before = isset( $old[ $role ]['capabilities'] ) ? array_keys( array_filter( (array) $old[ $role ]['capabilities'] ) ) : array();
			$gained = array_intersect( array_diff( array_keys( array_filter( (array) $def['capabilities'] ) ), $before ), $danger );
			if ( ! $gained ) {
				continue;
			}
			$weak = in_array( $role, array( 'subscriber', 'customer', 'contributor', 'author' ), true ) || get_option( 'default_role' ) === $role;
			Events::record( array(
				'module'    => 'options',
				'type'      => 'role_escalated',
				'severity'  => $weak ? 'critical' : ( $by_admin ? 'medium' : 'high' ),
				/* translators: 1: role, 2: capabilities */
				'title'     => array( __( 'Role "%1$s" gained %2$s', 'nightward' ), $role, implode( ', ', $gained ) ),
				'details'   => array(
					'explanation' => __( 'Administrator-level capabilities were added to a lower role.', 'nightward' ),
					'changed_by'  => Attribution::label( $c['component'] ),
				),
				'component' => $c['component'],
				'file'      => $c['file'],
				'line'      => $c['line'],
				'key'       => 'options|role|' . $role . '|' . implode( ',', $gained ),
			) );
		}
	}

	public static function on_network_plugins( $option, $value, $old ) {
		self::plugins_changed( array_keys( (array) $old ), array_keys( (array) $value ), Attribution::caller(), Util::request_context() );
	}

	private static function track( $option ) {
		if ( ! self::sampled() || 0 === strpos( $option, '_transient' ) || 0 === strpos( $option, '_site_transient' ) || 'cron' === $option ) {
			return;
		}
		if ( ! isset( self::$writes[ $option ] ) ) {
			$c = Attribution::caller( 25 );
			self::$writes[ $option ] = $c['component'] . '|' . $c['file'] . ':' . $c['line'];
		}
	}

	/** Persist the sample: one option write per ~20 page views. */
	public static function persist() {
		if ( ! self::sampled() ) {
			return;
		}
		$s = get_option( self::STATS, array() );
		if ( ! is_array( $s ) || empty( $s['since'] ) ) {
			$s = array( 'since' => time(), 'samples' => 0, 'options' => array() );
		}
		$s['samples']++;
		foreach ( self::$writes as $opt => $where ) {
			if ( ! isset( $s['options'][ $opt ] ) ) {
				if ( count( $s['options'] ) >= 60 ) {
					continue;
				}
				$s['options'][ $opt ] = array( 'n' => 0, 'where' => $where );
			}
			$s['options'][ $opt ]['n']++;
		}
		update_option( self::STATS, $s, false );
	}

	/** Hourly: options written on (almost) every front-end page view. */
	public static function evaluate() {
		$s = get_option( self::STATS, array() );
		if ( ! is_array( $s ) || empty( $s['samples'] ) || $s['samples'] < 15 ) {
			return;
		}
		foreach ( (array) $s['options'] as $opt => $o ) {
			$ratio = $o['n'] / $s['samples'];
			if ( $ratio < 0.6 ) {
				continue;
			}
			list( $component, $at ) = array_pad( explode( '|', $o['where'], 2 ), 2, '' );
			list( $file, $line )    = array_pad( explode( ':', $at, 2 ), 2, 0 );
			Events::record( array(
				'module'    => 'options',
				'type'      => 'write_every_request',
				'severity'  => 'low',
				/* translators: 1: plugin name, 2: option name, 3: percent */
				'title'     => array( __( '%1$s writes option "%2$s" on %3$s of page views', 'nightward' ), Attribution::label( $component ), $opt, round( $ratio * 100 ) . '%' ),
				'details'   => array(
					'explanation' => __( 'A database write on almost every visit wastes resources and breaks full-page caching. For licence or "phone home" code it can also mean the site is being tracked on every request.', 'nightward' ),
					'samples'     => $s['samples'],
				),
				'component' => $component,
				'file'      => $file,
				'line'      => (int) $line,
				'key'       => 'options|everyreq|' . $opt,
			) );
		}
		// Скидаємо вибірку раз на добу, щоб старі плагіни не висіли вічно.
		if ( time() - (int) $s['since'] > DAY_IN_SECONDS ) {
			delete_option( self::STATS );
		}
	}

	/** Daily: autoloaded options weight. */
	public static function autoload_check() {
		$top   = self::autoload_top( 10 );
		$total = self::autoload_total();
		update_option( 'nightward_autoload', array( 'total' => $total, 'top' => $top, 'at' => time() ), false );
		if ( $total < 800 * KB_IN_BYTES ) {
			return;
		}
		Events::record( array(
			'module'   => 'options',
			'type'     => 'autoload_heavy',
			'severity' => $total > 3 * MB_IN_BYTES ? 'medium' : 'low',
			/* translators: %s: size */
			'title'    => array( __( 'Autoloaded options weigh %s', 'nightward' ), Util::human_bytes( $total ) ),
			'details'  => array(
				'explanation' => __( 'WordPress loads these options on every request. Leftovers of removed plugins are the usual cause.', 'nightward' ),
				'largest'     => array_map( function ( $r ) {
					return $r['name'] . ' — ' . Util::human_bytes( $r['size'] );
				}, $top ),
			),
			'key'      => 'options|autoload|' . gmdate( 'oW' ),
		) );
	}

	private static function autoload_values() {
		return array( 'yes', 'on', 'auto-on', 'auto' );
	}

	public static function autoload_total() {
		global $wpdb;
		$in = implode( ',', array_map( function ( $v ) {
			return "'" . esc_sql( $v ) . "'";
		}, self::autoload_values() ) );
		return (int) $wpdb->get_var( "SELECT SUM(LENGTH(option_value)) FROM {$wpdb->options} WHERE autoload IN ($in)" ); // phpcs:ignore
	}

	public static function autoload_top( $n ) {
		global $wpdb;
		$in   = implode( ',', array_map( function ( $v ) {
			return "'" . esc_sql( $v ) . "'";
		}, self::autoload_values() ) );
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT option_name, LENGTH(option_value) AS size FROM {$wpdb->options} WHERE autoload IN ($in) ORDER BY size DESC LIMIT %d", $n ) ); // phpcs:ignore
		$out  = array();
		foreach ( $rows as $r ) {
			$out[] = array( 'name' => $r->option_name, 'size' => (int) $r->size );
		}
		return $out;
	}
}
