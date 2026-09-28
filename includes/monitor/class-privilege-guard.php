<?php
/**
 * Privilege Guard.
 *
 * - An administrator created or promoted anywhere except the Users screen,
 *   the REST API or WP-CLI by an administrator → critical, with the file and
 *   line of the plugin that did it.
 * - An administrator that appears in the database without passing through any
 *   WordPress function (direct SQL) → critical, found by the hourly audit.
 * - An administrator that exists in the database but is filtered out of the
 *   Users list → critical ("hidden admin").
 * - Password / e-mail of an administrator changed by plugin code, application
 *   passwords created, administrator logins from a new network.
 */

namespace Nightward\Monitor;

use Nightward\Attribution;
use Nightward\Events;
use Nightward\Settings;
use Nightward\Util;

defined( 'ABSPATH' ) || exit;

class Privilege_Guard {

	const SNAPSHOT = 'nightward_admins';

	private static $checked = array();

	public static function init() {
		add_action( 'user_register', array( __CLASS__, 'on_register' ), PHP_INT_MAX, 1 );
		add_action( 'set_user_role', array( __CLASS__, 'on_role' ), PHP_INT_MAX, 3 );
		add_action( 'add_user_role', array( __CLASS__, 'on_add_role' ), PHP_INT_MAX, 2 );
		add_action( 'added_user_meta', array( __CLASS__, 'on_meta' ), PHP_INT_MAX, 4 );
		add_action( 'updated_user_meta', array( __CLASS__, 'on_meta' ), PHP_INT_MAX, 4 );
		add_action( 'granted_super_admin', array( __CLASS__, 'on_super' ), PHP_INT_MAX, 1 );
		add_action( 'profile_update', array( __CLASS__, 'on_profile' ), PHP_INT_MAX, 3 );
		add_action( 'wp_set_password', array( __CLASS__, 'on_set_password' ), PHP_INT_MAX, 2 );
		add_action( 'wp_create_application_password', array( __CLASS__, 'on_app_password' ), PHP_INT_MAX, 2 );
		add_action( 'wp_login', array( __CLASS__, 'on_login' ), PHP_INT_MAX, 2 );
	}

	private static function is_admin_user( $user_id ) {
		$u = get_userdata( $user_id );
		return $u && ( in_array( 'administrator', (array) $u->roles, true ) || ( is_multisite() && is_super_admin( $user_id ) ) );
	}

	/**
	 * Legit paths: the Users screens, profile screens, REST users endpoint and
	 * WP-CLI — all only when core itself is the caller (no plugin frame).
	 */
	private static function assess( $new_user_id ) {
		$c   = Attribution::caller();
		$ctx = Util::request_context();
		$cur = get_current_user_id();
		$by  = $cur ? get_userdata( $cur ) : null;
		$can = $cur && $cur !== (int) $new_user_id && user_can( $cur, 'promote_users' );

		if ( 'cli' === $ctx ) {
			return array( 'medium', $c, __( 'Done from WP-CLI (server shell access).', 'nightward' ) );
		}
		if ( 'eval' === $c['component'] || $c['via_eval'] ) {
			return array( 'critical', $c, __( 'Done by code executed via eval().', 'nightward' ) );
		}
		if ( 'core' === $c['component'] && $can && in_array( $ctx, array( 'admin', 'rest', 'ajax' ), true ) ) {
			/* translators: %s: user login */
			return array( 'info', $c, array( __( 'Done by %s through the standard WordPress screens.', 'nightward' ), $by ? $by->user_login : '?' ) );
		}
		if ( 'core' !== $c['component'] && $can && 'admin' === $ctx ) {
			/* translators: %s: user login */
			return array( 'high', $c, array( __( 'Done by a plugin while %s was working in the dashboard. Make sure this was intended (e.g. a role editor plugin).', 'nightward' ), $by ? $by->user_login : '?' ) );
		}
		if ( ! $can ) {
			return array( 'critical', $c, $cur
				/* translators: %s: user login */
				? array( __( 'The logged-in user %s is not allowed to grant roles, yet an administrator was created. Classic privilege-escalation or backdoor behaviour.', 'nightward' ), $by ? $by->user_login : '?' )
				: __( 'Nobody was logged in: an administrator was created by an anonymous request.', 'nightward' ) );
		}
		return array( 'critical', $c, __( 'An administrator was created outside the standard Users screens.', 'nightward' ) );
	}

	/**
	 * Hooks fire in the order meta → set_user_role → user_register, so the
	 * caller is captured at the first one and the verdict is made at shutdown
	 * with the most specific description of what happened.
	 */
	private static function granted( $user_id, $how ) {
		$user_id = (int) $user_id;
		if ( ! isset( self::$checked[ $user_id ] ) ) {
			self::$checked[ $user_id ] = array( 'assess' => self::assess( $user_id ), 'how' => array() );
			if ( 1 === count( self::$checked ) ) {
				add_action( 'shutdown', array( __CLASS__, 'settle' ), 1 );
			}
		}
		self::$checked[ $user_id ]['how'][] = $how;
	}

	public static function settle() {
		$snap = (array) get_option( self::SNAPSHOT, array() );
		foreach ( self::$checked as $user_id => $p ) {
			clean_user_cache( $user_id );
			if ( isset( $snap[ $user_id ] ) || ! self::is_admin_user( $user_id ) ) {
				continue;
			}
			$u = get_userdata( $user_id );
			list( $sev, $c, $why ) = $p['assess'];
			$order = array( 'created', 'role', 'added', 'super', 'meta' );
			$how   = 'meta';
			foreach ( $order as $o ) {
				if ( in_array( $o, $p['how'], true ) ) {
					$how = $o;
					break;
				}
			}
			$labels = array(
				'created' => __( 'account created', 'nightward' ),
				'role'    => __( 'role changed', 'nightward' ),
				'added'   => __( 'role added', 'nightward' ),
				'super'   => __( 'network super admin', 'nightward' ),
				'meta'    => __( 'capabilities written directly', 'nightward' ),
			);
			self::remember( $user_id );
			Events::record( array(
				'module'    => 'privilege',
				'type'      => 'admin_granted',
				'severity'  => $sev,
				/* translators: 1: user login, 2: how */
				'title'     => array( __( 'New administrator: %1$s (%2$s)', 'nightward' ), $u->user_login, $labels[ $how ] ),
				'details'   => array(
					'explanation' => $why,
					'user'        => $u->user_login,
					'email'       => $u->user_email,
					'user_id'     => $user_id,
					'done_by'     => Attribution::label( $c['component'] ),
					'context'     => Util::request_context(),
					'request'     => Util::request_path(),
					'ip'          => Util::client_ip(),
				),
				'component' => $c['component'],
				'file'      => $c['file'],
				'line'      => $c['line'],
				'key'       => 'privilege|granted|' . $user_id,
			) );
		}
		self::$checked = array();
	}

	public static function on_register( $user_id ) {
		self::granted( $user_id, 'created' );
	}

	public static function on_role( $user_id, $role, $old_roles = array() ) {
		if ( 'administrator' === $role ) {
			self::granted( $user_id, 'role' );
		}
	}

	public static function on_add_role( $user_id, $role ) {
		if ( 'administrator' === $role ) {
			self::granted( $user_id, 'added' );
		}
	}

	/** Direct write of wp_capabilities via update_user_meta(). */
	public static function on_meta( $meta_id, $user_id, $key, $value ) {
		global $wpdb;
		if ( $key !== $wpdb->get_blog_prefix() . 'capabilities' ) {
			return;
		}
		$caps = maybe_unserialize( $value );
		if ( is_array( $caps ) && ! empty( $caps['administrator'] ) ) {
			self::granted( $user_id, 'meta' );
		}
	}

	public static function on_super( $user_id ) {
		self::granted( $user_id, 'super' );
	}

	public static function remember( $user_id ) {
		$snap = (array) get_option( self::SNAPSHOT, array() );
		$u    = get_userdata( $user_id );
		$snap[ (int) $user_id ] = $u ? $u->user_login : '?';
		update_option( self::SNAPSHOT, $snap, false );
	}

	/** Changes to an administrator's password/e-mail made by plugin code. */
	public static function on_profile( $user_id, $old, $new = array() ) {
		if ( ! self::is_admin_user( $user_id ) || ! $old instanceof \WP_User ) {
			return;
		}
		$u       = get_userdata( $user_id );
		$changed = array();
		if ( $u->user_pass !== $old->user_pass ) {
			$changed[] = __( 'password', 'nightward' );
		}
		if ( $u->user_email !== $old->user_email ) {
			$changed[] = __( 'e-mail', 'nightward' );
		}
		if ( $changed ) {
			self::credential_change( $user_id, $changed, $old->user_email );
		}
	}

	public static function on_set_password( $password, $user_id ) {
		if ( self::is_admin_user( $user_id ) ) {
			self::credential_change( $user_id, array( __( 'password', 'nightward' ) ), '' );
		}
	}

	private static function credential_change( $user_id, array $what, $old_email ) {
		$c = Attribution::caller();
		if ( 'core' === $c['component'] ) {
			return; // профіль, скидання пароля, Users screen
		}
		$cur = get_current_user_id();
		$sev = 'medium';
		if ( 'eval' === $c['component'] || $c['via_eval'] || ( $cur !== (int) $user_id && ! user_can( $cur, 'edit_users' ) ) ) {
			$sev = 'critical';
		}
		$u = get_userdata( $user_id );
		Events::record( array(
			'module'    => 'privilege',
			'type'      => 'admin_credentials',
			'severity'  => $sev,
			/* translators: 1: what changed, 2: user login, 3: plugin name */
			'title'     => array( __( 'Administrator %2$s: %1$s changed by %3$s', 'nightward' ), implode( ', ', $what ), $u->user_login, Attribution::label( $c['component'] ) ),
			'details'   => array(
				'explanation' => __( 'Credentials of an administrator were changed by plugin/theme code, not through the profile or password-reset screens.', 'nightward' ),
				'old_email'   => $old_email,
				'new_email'   => $u->user_email,
				'context'     => Util::request_context(),
				'request'     => Util::request_path(),
				'ip'          => Util::client_ip(),
			),
			'component' => $c['component'],
			'file'      => $c['file'],
			'line'      => $c['line'],
			'key'       => 'privilege|cred|' . $user_id . '|' . $c['file'] . '|' . gmdate( 'YmdH' ),
		) );
	}

	public static function on_app_password( $user_id, $item = array() ) {
		if ( ! self::is_admin_user( $user_id ) ) {
			return;
		}
		$c   = Attribution::caller();
		$u   = get_userdata( $user_id );
		$sev = 'core' === $c['component'] && get_current_user_id() ? 'medium' : 'high';
		Events::record( array(
			'module'    => 'privilege',
			'type'      => 'app_password',
			'severity'  => $sev,
			/* translators: 1: user login, 2: app name */
			'title'     => array( __( 'Application password "%2$s" created for administrator %1$s', 'nightward' ), $u->user_login, isset( $item['name'] ) ? $item['name'] : '?' ),
			'details'   => array(
				'explanation' => __( 'Application passwords give permanent REST/XML-RPC access that bypasses two-factor login and survives a password change. Remove it in the user profile if you did not create it.', 'nightward' ),
				'created_by'  => Attribution::label( $c['component'] ),
				'ip'          => Util::client_ip(),
			),
			'component' => $c['component'],
			'file'      => $c['file'],
			'line'      => $c['line'],
			'key'       => 'privilege|apppw|' . $user_id . '|' . ( isset( $item['uuid'] ) ? $item['uuid'] : time() ),
		) );
	}

	/** Administrator login from a network (/24, /48) not seen for this account before. */
	public static function on_login( $login, $user ) {
		if ( ! $user instanceof \WP_User || ! self::is_admin_user( $user->ID ) ) {
			return;
		}
		$ip = Util::client_ip();
		if ( ! $ip ) {
			return;
		}
		$net   = self::network_of( $ip );
		$known = get_user_meta( $user->ID, 'nightward_known_nets', true );
		$known = is_array( $known ) ? $known : array();
		if ( in_array( $net, $known, true ) ) {
			return;
		}
		$first = empty( $known );
		$known[] = $net;
		update_user_meta( $user->ID, 'nightward_known_nets', array_slice( array_values( array_unique( $known ) ), -15 ) );
		if ( $first || Settings::in_learning() ) {
			return;
		}
		Events::record( array(
			'module'   => 'privilege',
			'type'     => 'new_network',
			'severity' => 'low',
			/* translators: 1: user login, 2: IP address */
			'title'    => array( __( 'Administrator %1$s logged in from a new network: %2$s', 'nightward' ), $login, $ip ),
			'details'  => array(
				'network'    => $net,
				'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 200 ) : '',
				'known'      => count( $known ) - 1,
			),
			'key'      => 'privilege|net|' . $user->ID . '|' . $net,
		) );
	}

	public static function network_of( $ip ) {
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return implode( '.', array_slice( explode( '.', $ip ), 0, 3 ) ) . '.0/24';
		}
		$bin = @inet_pton( $ip );
		return $bin ? inet_ntop( substr( $bin, 0, 6 ) . str_repeat( "\0", 10 ) ) . '/48' : $ip;
	}

	/** Administrators as stored in the database, bypassing every filter. */
	public static function db_admins() {
		global $wpdb;
		$key  = $wpdb->get_blog_prefix() . 'capabilities';
		$rows = $wpdb->get_results( $wpdb->prepare( // phpcs:ignore
			"SELECT u.ID, u.user_login, u.user_email, u.user_registered, m.meta_value FROM {$wpdb->users} u JOIN {$wpdb->usermeta} m ON m.user_id = u.ID WHERE m.meta_key = %s AND m.meta_value LIKE %s",
			$key, '%administrator%'
		) );
		$out = array();
		foreach ( $rows as $r ) {
			$caps = maybe_unserialize( $r->meta_value );
			if ( is_array( $caps ) && ! empty( $caps['administrator'] ) ) {
				$out[ (int) $r->ID ] = $r;
			}
		}
		if ( is_multisite() ) {
			foreach ( (array) get_site_option( 'site_admins', array() ) as $login ) {
				$u = get_user_by( 'login', $login );
				if ( $u && ! isset( $out[ $u->ID ] ) ) {
					$out[ $u->ID ] = (object) array( 'ID' => $u->ID, 'user_login' => $u->user_login, 'user_email' => $u->user_email, 'user_registered' => $u->user_registered );
				}
			}
		}
		return $out;
	}

	/** Hourly: direct-SQL admins, hidden admins, snapshot upkeep. */
	public static function audit_admins() {
		$db   = self::db_admins();
		$snap = get_option( self::SNAPSHOT, null );
		if ( ! is_array( $snap ) ) {
			$snap = array();
			foreach ( $db as $id => $r ) {
				$snap[ $id ] = $r->user_login;
			}
			update_option( self::SNAPSHOT, $snap, false );
			return;
		}
		foreach ( $db as $id => $r ) {
			if ( isset( $snap[ $id ] ) ) {
				continue;
			}
			$snap[ $id ] = $r->user_login;
			if ( Settings::in_learning() ) {
				continue;
			}
			Events::record( array(
				'module'   => 'privilege',
				'type'     => 'admin_direct_db',
				'severity' => 'critical',
				/* translators: %s: user login */
				'title'    => array( __( 'Administrator %s appeared without any WordPress user function being called', 'nightward' ), $r->user_login ),
				'details'  => array(
					'explanation' => __( 'The account got administrator rights through a direct database write (SQL), bypassing all WordPress hooks. Legitimate plugins and the admin screens never do this.', 'nightward' ),
					'user'        => $r->user_login,
					'email'       => $r->user_email,
					'registered'  => $r->user_registered,
				),
				'key'      => 'privilege|granted|' . $id,
			) );
		}
		// Прибрані з адмінів — прибрати зі знімка, щоб повторне призначення знову було видно.
		foreach ( array_keys( $snap ) as $id ) {
			if ( ! isset( $db[ $id ] ) ) {
				unset( $snap[ $id ] );
			}
		}
		update_option( self::SNAPSHOT, $snap, false );

		// Hidden admins: DB says administrator, the filtered Users query doesn't list them.
		$visible = get_users( array( 'role' => 'administrator', 'fields' => 'ID', 'number' => 500 ) );
		if ( is_multisite() ) {
			foreach ( (array) get_site_option( 'site_admins', array() ) as $login ) {
				$u = get_user_by( 'login', $login );
				if ( $u ) {
					$visible[] = $u->ID;
				}
			}
		}
		$visible = array_map( 'intval', (array) $visible );
		foreach ( $db as $id => $r ) {
			if ( in_array( (int) $id, $visible, true ) ) {
				continue;
			}
			Events::record( array(
				'module'   => 'privilege',
				'type'     => 'hidden_admin',
				'severity' => 'critical',
				/* translators: %s: user login */
				'title'    => array( __( 'Hidden administrator: %s is not shown in the Users list', 'nightward' ), $r->user_login ),
				'details'  => array(
					'explanation' => __( 'The account is an administrator in the database, but a filter removes it from user queries so it does not appear in Users. This is a common backdoor pattern. Check callbacks on pre_user_query and users_list_table_query_args on the Hooks screen.', 'nightward' ),
					'user'        => $r->user_login,
					'email'       => $r->user_email,
					'registered'  => $r->user_registered,
				),
				'key'      => 'privilege|hidden|' . $id,
			) );
		}
	}
}
