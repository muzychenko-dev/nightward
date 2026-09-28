<?php
/**
 * Sensitive Hooks Watch.
 *
 * Remembers who is attached to the hooks that decide who is logged in, what a
 * user may do, which plugins and users are visible, and where updates and
 * mail go. A callback that shows up there later — not right after an install
 * or update of its plugin — is reported with its file and line.
 *
 * Additionally, on a sample of requests every hook is checked for callbacks
 * compiled from eval()'d code or create_function(): there is no legitimate
 * reason for those.
 */

namespace Nightward\Monitor;

use Nightward\Attribution;
use Nightward\Events;
use Nightward\Settings;
use Nightward\Util;

defined( 'ABSPATH' ) || exit;

class Hooks_Watch {

	const BASELINE = 'nightward_hooks_baseline';
	const RELEARN  = 'nightward_relearn';

	/** hook => group */
	public static function watched() {
		return array(
			// Who is logged in and what they may do.
			'authenticate'                        => 'auth',
			'wp_authenticate_user'                => 'auth',
			'determine_current_user'              => 'auth',
			'check_password'                      => 'auth',
			'user_has_cap'                        => 'auth',
			'map_meta_cap'                        => 'auth',
			'rest_authentication_errors'          => 'auth',
			'application_password_is_api_request' => 'auth',
			'auth_cookie_valid'                   => 'auth',
			'wp_login'                            => 'auth',
			// Hiding things from the administrator.
			'all_plugins'                         => 'conceal',
			'pre_user_query'                      => 'conceal',
			'users_list_table_query_args'         => 'conceal',
			'views_users'                         => 'conceal',
			'show_advanced_plugins'               => 'conceal',
			'site_transient_update_plugins'       => 'conceal',
			'site_transient_update_core'          => 'conceal',
			// Where code and data travel.
			'upgrader_pre_download'               => 'channel',
			'upgrader_package_options'            => 'channel',
			'pre_set_site_transient_update_plugins' => 'channel',
			'pre_set_site_transient_update_themes' => 'channel',
			'http_request_args'                   => 'channel',
			'pre_wp_mail'                         => 'channel',
			'phpmailer_init'                      => 'channel',
			'xmlrpc_methods'                      => 'channel',
		);
	}

	public static function group_label( $g ) {
		$l = array(
			'auth'    => __( 'authentication and permissions', 'nightward' ),
			'conceal' => __( 'what the administrator can see', 'nightward' ),
			'channel' => __( 'updates, HTTP and mail', 'nightward' ),
		);
		return isset( $l[ $g ] ) ? $l[ $g ] : $g;
	}

	public static function init() {
		add_action( 'wp_loaded', array( __CLASS__, 'check' ), PHP_INT_MAX );
	}

	/** Callback signature that survives line shifts across requests. */
	private static function sig( array $info ) {
		// Scope of a closure depends on who included the file (WP-CLI wraps it), so it is not part of the identity.
		$name = preg_replace( '/^\{closure\}.*$/', '{closure}', $info['name'] );
		return md5( $info['component'] . '|' . $name . '|' . $info['file'] );
	}

	public static function snapshot() {
		global $wp_filter;
		$out = array();
		foreach ( self::watched() as $hook => $group ) {
			if ( empty( $wp_filter[ $hook ] ) || ! ( $wp_filter[ $hook ] instanceof \WP_Hook ) ) {
				continue;
			}
			foreach ( $wp_filter[ $hook ]->callbacks as $prio => $cbs ) {
				foreach ( $cbs as $cid => $cb ) {
					if ( 0 === strpos( (string) $cid, 'nightward_s_' ) ) {
						continue;
					}
					$info = Attribution::callback_info( $cb['function'] );
					if ( in_array( $info['component'], array( 'core', 'nightward', 'php' ), true ) ) {
						continue;
					}
					$info['priority'] = $prio;
					$info['hook']     = $hook;
					$info['group']    = $group;
					$out[ $hook . '|' . self::sig( $info ) ] = $info;
				}
			}
		}
		return $out;
	}

	public static function check() {
		$now = self::snapshot();
		// Fast path: this exact set of callbacks was already checked (small autoloaded option).
		$sig  = md5( implode( ',', array_keys( $now ) ) );
		$sigs = get_option( 'nightward_hooks_sigs', array() );
		$sigs = is_array( $sigs ) ? $sigs : array();
		if ( in_array( $sig, $sigs, true ) ) {
			if ( 0 === wp_rand( 0, 39 ) || ( is_admin() && isset( $_GET['page'] ) && 'nightward' === $_GET['page'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
				self::eval_sweep();
			}
			return;
		}
		$sigs[] = $sig;
		update_option( 'nightward_hooks_sigs', array_slice( $sigs, -30 ), true );
		$base     = get_option( self::BASELINE, null );
		$learning = Settings::in_learning();
		if ( ! is_array( $base ) ) {
			$base = array();
		}
		$relearn = (array) get_option( self::RELEARN, array() );
		$changed   = false;
		$eval_seen = false;
		foreach ( $now as $k => $info ) {
			if ( isset( $base[ $k ] ) ) {
				continue;
			}
			$base[ $k ] = array( 'hook' => $info['hook'], 'name' => $info['name'], 'file' => $info['file'], 'component' => $info['component'], 't' => time() );
			$changed    = true;
			if ( 'eval' === $info['component'] ) {
				$eval_seen = true; // звітує eval_sweep() нижче — одна подія на один eval-callback
				continue;
			}
			$fresh = isset( $relearn[ $info['component'] ] ) && ( time() - (int) $relearn[ $info['component'] ] ) < 6 * HOUR_IN_SECONDS;
			if ( $learning ) {
				continue;
			}
			if ( $fresh ) {
				self::report( $info, in_array( $info['group'], array( 'auth', 'conceal' ), true ) ? 'low' : 'info', __( 'Registered right after this plugin/theme was installed, activated or updated. Recorded as the new baseline.', 'nightward' ) );
				continue;
			}
			$sev = 'medium';
			if ( 'auth' === $info['group'] || 'conceal' === $info['group'] ) {
				$sev = 'high';
			}
			if ( 0 === strpos( $info['component'], 'mu:' ) || 0 === strpos( $info['component'], 'dropin:' ) || 0 === strpos( $info['component'], 'other:' ) ) {
				$sev = 'high';
			}
			self::report( $info, $sev, __( 'This callback appeared although the plugin/theme it belongs to was not installed or updated recently. Check the code at the given line.', 'nightward' ) );
		}
		if ( $changed ) {
			update_option( self::BASELINE, array_slice( $base, -1500, null, true ), false );
		}
		// 1 з 40 запитів — повний прохід на callbacks з eval()/create_function().
		if ( $eval_seen || 0 === wp_rand( 0, 39 ) || ( is_admin() && isset( $_GET['page'] ) && 'nightward' === $_GET['page'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			self::eval_sweep();
		}
	}

	private static function report( array $info, $sev, $explain ) {
		Events::record( array(
			'module'    => 'hooks',
			'type'      => 'eval' === $info['component'] ? 'eval_callback' : 'new_callback',
			'severity'  => $sev,
			/* translators: 1: plugin/theme name, 2: hook name */
			'title'     => array( __( '%1$s hooked into %2$s', 'nightward' ), Attribution::label( $info['component'] ), $info['hook'] ),
			'details'   => array(
				'explanation' => $explain,
				'hook'        => $info['hook'],
				'area'        => self::group_label( $info['group'] ),
				'callback'    => $info['name'],
				'priority'    => $info['priority'],
				'context'     => Util::request_context(),
			),
			'component' => $info['component'],
			'file'      => $info['file'],
			'line'      => $info['line'],
			'key'       => 'hooks|' . $info['hook'] . '|' . self::sig( $info ),
		) );
	}

	/** Any hook, any callback compiled from eval() or create_function(). */
	public static function eval_sweep() {
		global $wp_filter;
		$seen = 0;
		foreach ( $wp_filter as $hook => $obj ) {
			if ( ! ( $obj instanceof \WP_Hook ) ) {
				continue;
			}
			foreach ( $obj->callbacks as $prio => $cbs ) {
				foreach ( $cbs as $cid => $cb ) {
					$fn = $cb['function'];
					$bad = '';
					if ( is_string( $fn ) && "\0" === substr( $fn, 0, 1 ) ) {
						$bad = 'create_function';
					} elseif ( $fn instanceof \Closure ) {
						try {
							$rf = new \ReflectionFunction( $fn );
							if ( false !== strpos( (string) $rf->getFileName(), "eval()'d code" ) ) {
								$bad = 'eval';
							}
						} catch ( \Throwable $e ) {
							$bad = '';
						}
					}
					if ( ! $bad || ++$seen > 20 ) {
						continue;
					}
					$origin = 'eval' === $bad ? (string) $rf->getFileName() : '';
					$o_line = preg_match( '/\((\d+)\) : eval\(\)\'d code$/', $origin, $m ) ? (int) $m[1] : 0;
					$o_file = $origin ? Attribution::rel( preg_replace( '/\(\d+\) : eval\(\)\'d code$/', '', $origin ) ) : '';
					Events::record( array(
						'module'    => 'hooks',
						'type'      => 'eval_callback',
						'severity'  => 'critical',
						/* translators: %s: hook name */
						'title'     => array( __( 'Code created at runtime with eval() is attached to %s', 'nightward' ), $hook ),
						'details'   => array(
							'explanation' => __( 'A hook callback has no source file: it was compiled from a string at runtime. This is how many backdoors hide from file scanners. The file that called eval() is the one to inspect.', 'nightward' ),
							'hook'        => $hook,
							'priority'    => $prio,
							'method'      => $bad,
							'eval_origin' => $o_file ? $o_file . ':' . $o_line : '',
						),
						'component' => 'eval',
						'file'      => $o_file,
						'line'      => $o_line,
						'key'       => 'hooks|evalsweep|' . $hook . '|' . ( $o_file ? $o_file . ':' . $o_line : $cid ),
					) );
				}
			}
		}
	}

	/** Called from the upgrader / activation hooks: this component may legitimately add hooks now. */
	public static function mark_relearn( array $components ) {
		$r = (array) get_option( self::RELEARN, array() );
		foreach ( $components as $c ) {
			$r[ $c ] = time();
		}
		foreach ( $r as $c => $t ) {
			if ( time() - (int) $t > DAY_IN_SECONDS ) {
				unset( $r[ $c ] );
			}
		}
		update_option( self::RELEARN, $r, false );
	}

	/** For the admin screen: current callbacks on watched hooks, grouped. */
	public static function current_map() {
		$out = array();
		foreach ( self::snapshot() as $info ) {
			$out[ $info['group'] ][] = $info;
		}
		return $out;
	}
}
