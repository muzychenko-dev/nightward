<?php
/**
 * Executable files where they must not be:
 * - PHP (and other executable scripts) in uploads;
 * - .htaccess in uploads that turns on script execution;
 * - PHP in the wp-content root that is not a known drop-in;
 * - new files in mu-plugins (they run on every request and are hidden from
 *   the regular Plugins list);
 * - PHP in cache / upgrade / languages folders.
 */

namespace Nightward\Scanner;

use Nightward\Attribution;
use Nightward\Events;
use Nightward\Settings;
use Nightward\Util;

defined( 'ABSPATH' ) || exit;

class Upload_Guard {

	const PROBE_PREFIX = 'nightward-probe-';

	public static function dropins() {
		return array( 'advanced-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php', 'object-cache.php', 'php-error.php', 'fatal-error-handler.php', 'sunrise.php', 'blog-deleted.php', 'blog-inactive.php', 'blog-suspended.php', 'index.php' );
	}

	public static function scan( $quick = true ) {
		$t0     = microtime( true );
		$budget = $quick ? 8 : 60;
		$found  = 0;

		$up = wp_get_upload_dir();
		if ( ! empty( $up['basedir'] ) && is_dir( $up['basedir'] ) ) {
			$found += self::scan_uploads( $up['basedir'], $t0, $budget );
		}
		$found += self::scan_content_root();
		$found += self::scan_mu();
		foreach ( array( 'cache', 'upgrade', 'languages', 'upgrade-temp-backup' ) as $d ) {
			$dir = WP_CONTENT_DIR . '/' . $d;
			if ( is_dir( $dir ) && ( microtime( true ) - $t0 ) < $budget ) {
				$found += self::scan_dir_for_php( $dir, $d, $t0, $budget );
			}
		}
		self::resolve_removed();
		update_option( 'nightward_uploads_last', array( 'at' => time(), 'found' => $found, 'quick' => (bool) $quick ), false );
		return $found;
	}

	/** Files that were deleted since they were reported: close their events. */
	private static function resolve_removed() {
		global $wpdb;
		$t    = \Nightward\DB::events();
		$rows = $wpdb->get_results( "SELECT id, file FROM {$t} WHERE module IN ('uploads','integrity') AND status IN ('open','acknowledged') AND file <> '' LIMIT 500" ); // phpcs:ignore
		$ids  = array();
		foreach ( $rows as $r ) {
			$abs = 0 === strpos( $r->file, 'wp-content/' ) ? WP_CONTENT_DIR . substr( $r->file, 10 ) : ABSPATH . $r->file;
			if ( ! file_exists( $abs ) || ( 0 === strpos( $r->file, 'wp-content/uploads/' ) && Util::is_inert_php( $abs ) ) ) {
				$ids[] = (int) $r->id; // файл прибрали або це лише сховище даних з exit на початку
			}
		}
		if ( $ids ) {
			Events::set_status( $ids, 'resolved' );
		}
	}

	private static function iterator( $dir ) {
		return new \RecursiveIteratorIterator(
			new \RecursiveCallbackFilterIterator(
				new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
				function ( $cur ) {
					return ! ( $cur->isDir() && in_array( $cur->getFilename(), array( 'node_modules', '.git' ), true ) );
				}
			),
			\RecursiveIteratorIterator::SELF_FIRST
		);
	}

	private static function scan_uploads( $base, $t0, $budget ) {
		$exec  = Util::executable_extensions();
		$found = 0;
		try {
			foreach ( self::iterator( $base ) as $f ) {
				if ( ( microtime( true ) - $t0 ) > $budget ) {
					break;
				}
				if ( ! $f->isFile() ) {
					continue;
				}
				$name = $f->getFilename();
				$path = $f->getPathname();
				if ( 0 === strpos( $name, self::PROBE_PREFIX ) ) {
					continue;
				}
				if ( '.htaccess' === $name ) {
					$found += self::check_htaccess( $path );
					continue;
				}
				if ( '.user.ini' === $name || 'php.ini' === $name ) {
					$found += self::report( $path, 'ini_in_uploads', 'high', __( 'PHP configuration file inside uploads. It can enable auto_prepend_file to run a payload on every request.', 'nightward' ) );
					continue;
				}
				$parts = explode( '.', strtolower( $name ) );
				$ext   = end( $parts );
				if ( in_array( $ext, $exec, true ) ) {
					if ( Util::is_inert_php( $path ) ) {
						continue;
					}
					$found += self::report( $path, 'exec_in_uploads', 'high', __( 'Executable script in the uploads folder. Uploads should contain only media and documents; a script here can usually be run directly from the browser.', 'nightward' ) );
					continue;
				}
				// shell.php.jpg — виконується на деяких конфігураціях Apache (AddHandler).
				if ( count( $parts ) > 2 && array_intersect( array_slice( $parts, 1, -1 ), $exec ) ) {
					$found += self::report( $path, 'double_ext', 'medium', __( 'Double extension (e.g. file.php.jpg). On some Apache setups such files are executed as PHP.', 'nightward' ) );
					continue;
				}
				// Image that is actually PHP.
				if ( in_array( $ext, array( 'jpg', 'jpeg', 'png', 'gif', 'ico', 'webp', 'svg', 'txt' ), true ) && $f->getSize() < 2 * MB_IN_BYTES ) {
					$head = (string) @file_get_contents( $path, false, null, 0, 4096 );
					if ( preg_match( '/<\?php\s|<\?=\s*\$|eval\s*\(\s*(base64_decode|gzinflate)/i', $head ) ) {
						$found += self::report( $path, 'php_in_media', 'high', __( 'A media file contains PHP code. Used together with an include() elsewhere to hide a payload.', 'nightward' ) );
					}
				}
			}
		} catch ( \Throwable $e ) {
			return $found;
		}
		return $found;
	}

	private static function check_htaccess( $path ) {
		$c = (string) @file_get_contents( $path, false, null, 0, 32768 );
		if ( preg_match( '/^\s*(AddHandler|SetHandler|AddType|ForceType)\b[^\n]*(php|x-httpd|cgi|script)/mi', $c ) || preg_match( '/auto_(prepend|append)_file|php_value|php_flag\s+engine\s+on/i', $c ) ) {
			return self::report( $path, 'htaccess_exec', 'high', __( '.htaccess inside uploads enables script execution or PHP settings. Normal ones only deny access.', 'nightward' ) );
		}
		return 0;
	}

	private static function scan_content_root() {
		$found = 0;
		foreach ( (array) glob( WP_CONTENT_DIR . '/*' ) as $f ) {
			if ( ! is_file( $f ) ) {
				continue;
			}
			$name = basename( $f );
			if ( ! preg_match( '/\.(php\d?|phtml|phar|pht|inc)$/i', $name ) || in_array( $name, self::dropins(), true ) || Util::is_inert_php( $f ) ) {
				continue;
			}
			// Відомі легітимні з популярних плагінів.
			if ( preg_match( '/^(wp-cache-config|wflogs|wordfence-waf|w3tc-config|cache-config|breeze-config|wp-rocket-config|litespeed.*)\.php$/i', $name ) ) {
				continue;
			}
			$found += self::report( $f, 'content_root_php', 'high', __( 'PHP file in the wp-content root that is not a WordPress drop-in. Nothing loads it normally, so it is meant to be called from outside.', 'nightward' ) );
		}
		return $found;
	}

	private static function scan_mu() {
		$dir = WPMU_PLUGIN_DIR;
		if ( ! is_dir( $dir ) ) {
			return 0;
		}
		$known = get_option( 'nightward_mu_known', null );
		$first = ! is_array( $known ) || count( $known ) <= 1 && ! get_option( 'nightward_mu_init' );
		$known = is_array( $known ) ? $known : array();
		$found = 0;
		$now   = array();
		foreach ( (array) glob( $dir . '/*' ) as $f ) {
			$name = basename( $f );
			if ( is_dir( $f ) ) {
				continue; // MU loads only top-level files
			}
			if ( ! preg_match( '/\.php$/i', $name ) ) {
				continue;
			}
			$now[] = $name;
			if ( in_array( $name, $known, true ) || $first || Settings::in_learning() ) {
				continue;
			}
			$found += self::report( $f, 'new_mu_plugin', 'high', __( 'New must-use plugin. It runs on every request, cannot be deactivated from the dashboard and is easy to overlook — a favourite place for persistence.', 'nightward' ) );
		}
		update_option( 'nightward_mu_known', array_values( array_unique( array_merge( $known, $now ) ) ), false );
		update_option( 'nightward_mu_init', 1, false );
		return $found;
	}

	private static function scan_dir_for_php( $dir, $label, $t0, $budget ) {
		$found = 0;
		try {
			foreach ( self::iterator( $dir ) as $f ) {
				if ( ( microtime( true ) - $t0 ) > $budget ) {
					break;
				}
				if ( ! $f->isFile() ) {
					continue;
				}
				$name = $f->getFilename();
				if ( ! preg_match( '/\.(php\d?|phtml|phar|pht)$/i', $name ) || Util::is_inert_php( $f->getPathname() ) ) {
					continue;
				}
				if ( 'languages' === $label && preg_match( '/\.l10n\.php$/', $name ) ) {
					continue; // WP 6.5+ PHP translation files
				}
				if ( in_array( $label, array( 'cache' ), true ) && self::looks_like_cache( $f->getPathname() ) ) {
					continue;
				}
				$found += self::report( $f->getPathname(), 'php_in_' . str_replace( '-', '_', $label ), 'upgrade' === $label || 'upgrade-temp-backup' === $label ? 'medium' : 'high',
					/* translators: %s: folder name */
					sprintf( __( 'PHP file inside wp-content/%s. This folder should not contain runnable code.', 'nightward' ), $label ) );
			}
		} catch ( \Throwable $e ) {
			return $found;
		}
		return $found;
	}

	/** Cache plugins store PHP arrays (`<?php return array(...)`); that is data, not code. */
	private static function looks_like_cache( $path ) {
		$head = (string) @file_get_contents( $path, false, null, 0, 300 );
		return (bool) preg_match( '/^<\?php\s*(\/\*.*?\*\/\s*|\/\/[^\n]*\n\s*)*(return\s+(array\s*\(|\[)|exit|die|defined\s*\(\s*[\'"]ABSPATH)/is', $head );
	}

	private static function report( $path, $type, $sev, $why ) {
		$ind = Integrity::is_php( $path ) || preg_match( '/\.(jpe?g|png|gif|ico|txt|svg|webp)$/i', $path ) ? Integrity::payload_indicators( $path ) : array();
		if ( $ind ) {
			$sev = 'critical';
		}
		$rel = Attribution::rel( $path );
		$url = content_url( substr( $rel, strlen( 'wp-content/' ) ) );
		Events::record( array(
			'module'    => 'uploads',
			'type'      => $type,
			'severity'  => $sev,
			/* translators: %s: file path */
			'title'     => array( __( 'Suspicious file: %s', 'nightward' ), $rel ),
			'details'   => array(
				'explanation' => $why,
				'size'        => Util::human_bytes( (int) @filesize( $path ) ),
				'modified'    => wp_date( 'Y-m-d H:i', (int) @filemtime( $path ) ),
				'owner'       => function_exists( 'posix_getpwuid' ) && @fileowner( $path ) !== false ? ( ( $o = @posix_getpwuid( fileowner( $path ) ) ) ? $o['name'] : '' ) : '',
				'indicators'  => $ind,
				'preview'     => mb_substr( preg_replace( '/\s+/', ' ', (string) @file_get_contents( $path, false, null, 0, 400 ) ), 0, 240 ),
				'url'         => $url,
			),
			'file'      => $rel,
			'key'       => 'uploads|' . $type . '|' . $rel . '|' . @md5_file( $path ),
		) );
		return 1;
	}
}
