<?php
/**
 * Hardening checks. Each one is a fact about this server, verified from the
 * outside where it matters (loopback requests), not a guess from settings.
 */

namespace Nightward\Scanner;

use Nightward\Events;
use Nightward\Util;

defined( 'ABSPATH' ) || exit;

class Hardening {

	const RESULTS = 'nightward_hardening';

	private static function loopback( $path, $method = 'GET', $body = null ) {
		$url  = preg_match( '#^https?://#', $path ) ? $path : home_url( $path );
		$args = array(
			'timeout'     => 8,
			'redirection' => 0,
			'sslverify'   => apply_filters( 'https_local_ssl_verify', false ),
			'headers'     => array( 'X-Nightward-Probe' => '1', 'Cache-Control' => 'no-cache' ),
			'method'      => $method,
		);
		if ( null !== $body ) {
			$args['body'] = $body;
		}
		$r = wp_remote_request( $url, $args );
		if ( is_wp_error( $r ) ) {
			return null;
		}
		return array(
			'code'    => (int) wp_remote_retrieve_response_code( $r ),
			'body'    => (string) wp_remote_retrieve_body( $r ),
			'headers' => wp_remote_retrieve_headers( $r ),
		);
	}

	private static function path_of( $abs ) {
		$rel  = ltrim( substr( wp_normalize_path( $abs ), strlen( wp_normalize_path( ABSPATH ) ) ), '/' );
		return $rel;
	}

	private static function r( $id, $status, $sev, $title, $detail, $fix = '' ) {
		$title  = is_array( $title ) ? array_map( array( 'Nightward\\Events', 'english' ), $title ) : Events::english( $title );
		$detail = is_array( $detail ) ? array_map( array( 'Nightward\\Events', 'english' ), $detail ) : Events::english( $detail );
		$fix    = Events::english( $fix );
		return compact( 'id', 'status', 'sev', 'title', 'detail', 'fix' );
	}

	public static function run() {
		$res = array();
		$lb  = self::loopback( '/' );
		$ok  = null !== $lb;

		// PHP
		$v = PHP_VERSION;
		if ( version_compare( $v, '8.1', '<' ) ) {
			/* translators: %s: PHP version */
			$res[] = self::r( 'php', 'fail', 'medium', array( __( 'PHP %s no longer receives security fixes', 'nightward' ), $v ), __( 'Vulnerabilities found in this PHP version are not patched anymore.', 'nightward' ), __( 'Ask your host to switch to PHP 8.2 or newer.', 'nightward' ) );
		} elseif ( version_compare( $v, '8.2', '<' ) ) {
			$res[] = self::r( 'php', 'warn', 'low', array( __( 'PHP %s is close to end of life', 'nightward' ), $v ), __( 'Plan the move to a newer PHP version.', 'nightward' ), __( 'Switch to PHP 8.3 or newer.', 'nightward' ) );
		} else {
			$res[] = self::r( 'php', 'pass', '', array( __( 'PHP %s is supported', 'nightward' ), $v ), '' );
		}

		// Core updates
		if ( ! function_exists( 'get_core_updates' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		$cu  = get_core_updates();
		$upd = is_array( $cu ) && isset( $cu[0]->response ) && 'upgrade' === $cu[0]->response;
		$res[] = $upd
			/* translators: %s: version */
			? self::r( 'core_update', 'warn', 'medium', array( __( 'WordPress %s is available', 'nightward' ), $cu[0]->current ), __( 'Security releases are published as minor updates.', 'nightward' ), __( 'Dashboard → Updates.', 'nightward' ) )
			: self::r( 'core_update', 'pass', '', __( 'WordPress is up to date', 'nightward' ), '' );

		// File editor
		$res[] = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT
			? self::r( 'file_edit', 'pass', '', __( 'Built-in code editor is disabled', 'nightward' ), '' )
			: self::r( 'file_edit', 'warn', 'low', __( 'Built-in plugin/theme code editor is enabled', 'nightward' ), __( 'A stolen administrator session turns directly into code execution.', 'nightward' ), "define( 'DISALLOW_FILE_EDIT', true ); // wp-config.php" );

		// Error display
		$display = ( defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ) ) || in_array( strtolower( (string) ini_get( 'display_errors' ) ), array( '1', 'on', 'stdout' ), true );
		$res[] = $display
			? self::r( 'debug_display', 'warn', 'medium', __( 'PHP errors are shown to visitors', 'nightward' ), __( 'Error messages reveal file paths and plugin internals.', 'nightward' ), "define( 'WP_DEBUG_DISPLAY', false );" )
			: self::r( 'debug_display', 'pass', '', __( 'PHP errors are not shown to visitors', 'nightward' ), '' );

		// Exposed files: checked on disk first, then through HTTP.
		$candidates = array(
			'wp-content/debug.log' => array( 'high', __( 'debug.log is publicly readable', 'nightward' ) ),
			'.env'                 => array( 'critical', __( '.env file is publicly readable', 'nightward' ) ),
			'.git/HEAD'            => array( 'high', __( '.git repository is publicly readable', 'nightward' ) ),
			'wp-config.php.bak'    => array( 'critical', __( 'Backup of wp-config.php is publicly readable', 'nightward' ) ),
			'wp-config.php.old'    => array( 'critical', __( 'Backup of wp-config.php is publicly readable', 'nightward' ) ),
			'wp-config.php.save'   => array( 'critical', __( 'Backup of wp-config.php is publicly readable', 'nightward' ) ),
			'wp-config.php.orig'   => array( 'critical', __( 'Backup of wp-config.php is publicly readable', 'nightward' ) ),
			'wp-config.php~'       => array( 'critical', __( 'Backup of wp-config.php is publicly readable', 'nightward' ) ),
			'wp-config.txt'        => array( 'critical', __( 'Backup of wp-config.php is publicly readable', 'nightward' ) ),
			'.wp-config.php.swp'   => array( 'critical', __( 'Editor swap file of wp-config.php is publicly readable', 'nightward' ) ),
		);
		if ( defined( 'WP_DEBUG_LOG' ) && is_string( WP_DEBUG_LOG ) && 0 === strpos( wp_normalize_path( WP_DEBUG_LOG ), wp_normalize_path( ABSPATH ) ) ) {
			$candidates[ self::path_of( WP_DEBUG_LOG ) ] = array( 'high', __( 'Debug log is publicly readable', 'nightward' ) );
		}
		foreach ( (array) glob( ABSPATH . '*.{sql,sql.gz,zip,tar,tar.gz,tgz}', GLOB_BRACE ) as $f ) {
			$candidates[ basename( $f ) ] = array( 'critical', __( 'Backup archive / database dump in the site root is publicly downloadable', 'nightward' ) );
		}
		$exposed = 0;
		foreach ( $candidates as $rel => $meta ) {
			$abs = 0 === strpos( $rel, 'wp-content/' ) ? WP_CONTENT_DIR . substr( $rel, 10 ) : ABSPATH . $rel;
			if ( ! file_exists( $abs ) || ! $ok ) {
				continue;
			}
			$u = 0 === strpos( $rel, 'wp-content/' ) ? content_url( substr( $rel, 11 ) ) : site_url( '/' . $rel );
			$r = self::loopback( $u, 'HEAD' );
			$r = $r && 200 === $r['code'] ? self::loopback( $u ) : $r;
			if ( $r && 200 === $r['code'] && strlen( $r['body'] ) > 0 && false === stripos( $r['body'], '<html' ) ) {
				$exposed++;
				$res[] = self::r( 'exposed_' . md5( $rel ), 'fail', $meta[0], array( '%1$s: %2$s', $meta[1], '/' . $rel ), __( 'Anyone can download it. Such files contain passwords, keys or paths.', 'nightward' ), __( 'Delete the file or deny access to it in the web server configuration.', 'nightward' ) );
			}
		}
		if ( ! $exposed ) {
			$res[] = self::r( 'exposed', $ok ? 'pass' : 'skip', '', __( 'No sensitive files are publicly downloadable', 'nightward' ), $ok ? '' : __( 'The site could not request itself (loopback), so this was checked on disk only.', 'nightward' ) );
		}

		// PHP execution in uploads.
		$res[] = self::uploads_exec( $ok );

		// Directory listing
		if ( $ok ) {
			$up = wp_get_upload_dir();
			$r  = self::loopback( trailingslashit( $up['baseurl'] ) );
			$res[] = $r && 200 === $r['code'] && preg_match( '/<title>\s*Index of/i', $r['body'] )
				? self::r( 'dir_listing', 'fail', 'medium', __( 'Directory listing is enabled for uploads', 'nightward' ), __( 'Anyone can browse all uploaded files, including private documents.', 'nightward' ), 'Options -Indexes' )
				: self::r( 'dir_listing', 'pass', '', __( 'Directory listing is disabled', 'nightward' ), '' );
		}

		// XML-RPC
		if ( $ok ) {
			$r  = self::loopback( site_url( '/xmlrpc.php' ), 'POST', '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' );
			$on = $r && 200 === $r['code'] && false !== strpos( $r['body'], 'wp.getUsersBlogs' );
			$res[] = $on
				? self::r( 'xmlrpc', 'warn', 'low', __( 'XML-RPC is enabled', 'nightward' ), __( 'Allows hundreds of password guesses in one request (system.multicall). Needed only by old apps and Jetpack.', 'nightward' ), __( 'Disable XML-RPC if you do not use it.', 'nightward' ) )
				: self::r( 'xmlrpc', 'pass', '', __( 'XML-RPC login is not available', 'nightward' ), '' );
		}

		// User enumeration
		if ( $ok ) {
			$r     = self::loopback( '/?rest_route=/wp/v2/users' );
			$users = $r && 200 === $r['code'] ? json_decode( $r['body'], true ) : null;
			$names = is_array( $users ) ? array_filter( wp_list_pluck( array_filter( $users, 'is_array' ), 'slug' ) ) : array();
			$res[] = $names
				? self::r( 'user_enum', 'warn', 'low', __( 'Login names are public via the REST API', 'nightward' ), array( /* translators: %s: user slugs */ __( 'Visible: %s. Half of a brute-force attack is knowing the login.', 'nightward' ), implode( ', ', array_slice( $names, 0, 5 ) ) ), __( 'Restrict /wp/v2/users to logged-in users.', 'nightward' ) )
				: self::r( 'user_enum', 'pass', '', __( 'User list is not exposed via REST', 'nightward' ), '' );
		}

		// "admin" login
		$admin = get_user_by( 'login', 'admin' );
		$res[] = $admin && user_can( $admin, 'manage_options' )
			? self::r( 'admin_login', 'warn', 'low', __( 'An administrator is called "admin"', 'nightward' ), __( 'It is the first login every bot tries.', 'nightward' ), __( 'Create a new administrator with another login and delete this one (attributing content to the new account).', 'nightward' ) )
			: self::r( 'admin_login', 'pass', '', __( 'No administrator named "admin"', 'nightward' ), '' );

		// HTTPS
		$https = 0 === strpos( home_url(), 'https://' );
		$res[] = $https
			? self::r( 'https', 'pass', '', __( 'Site uses HTTPS', 'nightward' ), '' )
			: self::r( 'https', 'fail', 'medium', __( 'Site address is not HTTPS', 'nightward' ), __( 'Passwords and session cookies travel unencrypted.', 'nightward' ), __( 'Install a certificate and change the site address to https://.', 'nightward' ) );

		// Security headers
		if ( $ok ) {
			$h       = $lb['headers'];
			$missing = array();
			if ( empty( $h['x-content-type-options'] ) ) {
				$missing[] = 'X-Content-Type-Options';
			}
			if ( empty( $h['x-frame-options'] ) && ( empty( $h['content-security-policy'] ) || false === stripos( (string) $h['content-security-policy'], 'frame-ancestors' ) ) ) {
				$missing[] = 'X-Frame-Options / frame-ancestors';
			}
			if ( empty( $h['referrer-policy'] ) ) {
				$missing[] = 'Referrer-Policy';
			}
			if ( $https && empty( $h['strict-transport-security'] ) ) {
				$missing[] = 'Strict-Transport-Security';
			}
			$res[] = $missing
				? self::r( 'headers', 'warn', 'info', __( 'Security headers missing', 'nightward' ), implode( ', ', $missing ), __( 'Add them in the web server or CDN configuration.', 'nightward' ) )
				: self::r( 'headers', 'pass', '', __( 'Security headers are set', 'nightward' ), '' );
		}

		// wp-config permissions
		$cfg = file_exists( ABSPATH . 'wp-config.php' ) ? ABSPATH . 'wp-config.php' : dirname( ABSPATH ) . '/wp-config.php';
		if ( file_exists( $cfg ) && DIRECTORY_SEPARATOR === '/' ) {
			$perm = fileperms( $cfg ) & 0777;
			if ( $perm & 0002 ) {
				$res[] = self::r( 'config_perm', 'fail', 'high', array( /* translators: %s: permissions */ __( 'wp-config.php is writable by everyone (%s)', 'nightward' ), decoct( $perm ) ), __( 'Any process on the server can change database credentials and inject code.', 'nightward' ), 'chmod 640 wp-config.php' );
			} elseif ( $perm & 0004 ) {
				$res[] = self::r( 'config_perm', 'warn', 'low', array( __( 'wp-config.php is readable by all users of the server (%s)', 'nightward' ), decoct( $perm ) ), __( 'On shared hosting other accounts may read your database password.', 'nightward' ), 'chmod 640 wp-config.php' );
			} else {
				/* translators: %s: octal permissions */
				$res[] = self::r( 'config_perm', 'pass', '', array( __( 'wp-config.php permissions are strict (%s)', 'nightward' ), decoct( $perm ) ), '' );
			}
		}

		// Inactive plugins
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$inactive = array();
		foreach ( get_plugins() as $file => $data ) {
			if ( ! is_plugin_active( $file ) && ! is_plugin_active_for_network( $file ) ) {
				$inactive[] = $data['Name'];
			}
		}
		$res[] = $inactive
			? self::r( 'inactive_plugins', 'warn', 'info', sprintf( /* translators: %d: count */ _n( '%d inactive plugin is still on disk', '%d inactive plugins are still on disk', count( $inactive ), 'nightward' ), count( $inactive ) ), implode( ', ', array_slice( $inactive, 0, 10 ) ) . '. ' . __( 'Their files can be requested directly and exploited even when deactivated.', 'nightward' ), __( 'Delete plugins you do not use.', 'nightward' ) )
			: self::r( 'inactive_plugins', 'pass', '', __( 'No inactive plugins on disk', 'nightward' ), '' );

		// WP-Cron
		$ch = \Nightward\Cron::health();
		$res[] = $ch['stale']
			? self::r( 'cron', 'fail', 'medium', __( 'Scheduled tasks are not running', 'nightward' ), __( 'Reports, scans and WordPress updates depend on WP-Cron. It has not run for more than three hours.', 'nightward' ), __( 'Set a real server cron job to call wp-cron.php every 5 minutes.', 'nightward' ) )
			: self::r( 'cron', 'pass', '', __( 'Scheduled tasks are running', 'nightward' ), '' );

		if ( ! $ok ) {
			$res[] = self::r( 'loopback', 'warn', 'low', __( 'The site cannot make requests to itself', 'nightward' ), __( 'Some checks were skipped. Loopback is also needed by WordPress for Site Health and plugin editor safety checks.', 'nightward' ) );
		}

		update_option( self::RESULTS, array( 'at' => time(), 'results' => $res ), false );

		foreach ( $res as $r ) {
			if ( 'fail' !== $r['status'] ) {
				continue;
			}
			Events::record( array(
				'module'   => 'hardening',
				'type'     => $r['id'],
				'severity' => $r['sev'],
				'title'    => $r['title'],
				'details'  => array( 'explanation' => $r['detail'], 'fix' => $r['fix'] ),
				'key'      => 'hardening|' . $r['id'],
			) );
		}
		// Виправлені — закриваємо.
		$pass = array();
		foreach ( $res as $r ) {
			if ( 'pass' === $r['status'] ) {
				$pass[] = $r['id'];
			}
		}
		global $wpdb;
		$t = \Nightward\DB::events();
		foreach ( $wpdb->get_results( "SELECT id, type FROM {$t} WHERE module = 'hardening' AND status IN ('open','acknowledged')" ) as $e ) { // phpcs:ignore
			$still = false;
			foreach ( $res as $r ) {
				if ( $r['id'] === $e->type && 'fail' === $r['status'] ) {
					$still = true;
				}
			}
			if ( ! $still && ( in_array( $e->type, $pass, true ) || 0 === strpos( $e->type, 'exposed_' ) ) ) {
				Events::set_status( array( (int) $e->id ), 'resolved' );
			}
		}
		return $res;
	}

	/** Actually try: write a harmless PHP file into uploads and request it. */
	private static function uploads_exec( $loopback_ok ) {
		$up = wp_get_upload_dir();
		if ( ! $loopback_ok || empty( $up['basedir'] ) || ! wp_is_writable( $up['basedir'] ) ) {
			return self::r( 'uploads_exec', 'skip', '', __( 'PHP execution in uploads: not tested', 'nightward' ), __( 'Loopback unavailable or uploads not writable.', 'nightward' ) );
		}
		$token = wp_generate_password( 12, false );
		$name  = Upload_Guard::PROBE_PREFIX . strtolower( $token ) . '.php';
		$file  = trailingslashit( $up['basedir'] ) . $name;
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( false === @file_put_contents( $file, '<?php echo "nw-" . "' . $token . '";' ) ) {
			return self::r( 'uploads_exec', 'skip', '', __( 'PHP execution in uploads: not tested', 'nightward' ), '' );
		}
		$r = self::loopback( trailingslashit( $up['baseurl'] ) . $name );
		wp_delete_file( $file );
		if ( $r && 200 === $r['code'] && false !== strpos( $r['body'], 'nw-' . $token ) ) {
			return self::r( 'uploads_exec', 'fail', 'medium', __( 'PHP files in uploads are executed', 'nightward' ), __( 'Any upload vulnerability in any plugin becomes full code execution. Nightward wrote a harmless test file, requested it and it ran.', 'nightward' ), __( 'Deny PHP in wp-content/uploads (nginx: location ~* /uploads/.*\.php$ { deny all; }; Apache: <FilesMatch "\.php$"> Require all denied </FilesMatch>).', 'nightward' ) );
		}
		return self::r( 'uploads_exec', 'pass', '', __( 'PHP files in uploads are not executed', 'nightward' ), '' );
	}

	public static function results() {
		$r = get_option( self::RESULTS );
		return is_array( $r ) ? $r : null;
	}

	/** 0–100 for the dashboard. */
	public static function score() {
		$r = self::results();
		if ( ! $r ) {
			return null;
		}
		$w     = array( 'critical' => 30, 'high' => 20, 'medium' => 10, 'low' => 5, 'info' => 2 );
		$score = 100;
		foreach ( $r['results'] as $x ) {
			if ( in_array( $x['status'], array( 'fail', 'warn' ), true ) && isset( $w[ $x['sev'] ] ) ) {
				$score -= 'warn' === $x['status'] ? (int) ceil( $w[ $x['sev'] ] / 2 ) : $w[ $x['sev'] ];
			}
		}
		return max( 0, $score );
	}
}
