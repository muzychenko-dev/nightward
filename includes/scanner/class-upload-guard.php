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

	/** cursor, full_pass_at, files_checked of the scan in progress. */
	private static $stats = array();

	public static function dropins() {
		return array( 'advanced-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php', 'object-cache.php', 'php-error.php', 'fatal-error-handler.php', 'sunrise.php', 'blog-deleted.php', 'blog-inactive.php', 'blog-suspended.php', 'index.php' );
	}

	public static function scan( $quick = true ) {
		$t0     = microtime( true );
		$budget = $quick ? 8 : 60;
		$found  = 0;

		$last = get_option( 'nightward_uploads_last' );
		$last = is_array( $last ) ? $last : array();
		self::$stats = array(
			'cursor'        => isset( $last['cursor'] ) ? (string) $last['cursor'] : '',
			'full_pass_at'  => isset( $last['full_pass_at'] ) ? (int) $last['full_pass_at'] : 0,
			'files_checked' => 0,
		);
		$up = wp_get_upload_dir();
		if ( ! empty( $up['basedir'] ) && is_dir( $up['basedir'] ) ) {
			$found += self::scan_uploads( $up['basedir'], $t0, $budget, $quick, isset( $last['at'] ) ? (int) $last['at'] : 0 );
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
		update_option( 'nightward_uploads_last', array_merge( self::$stats, array( 'at' => time(), 'found' => $found, 'quick' => (bool) $quick ) ), false );
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

	/**
	 * Uploads in a fixed order with a cursor, so that the whole media library gets
	 * checked even when one run cannot finish it. The quick hourly scan first looks
	 * at files changed in the current and previous month, then continues the cursor.
	 */
	private static function scan_uploads( $base, $t0, $budget, $quick, $last_at ) {
		$found = 0;
		$base  = untrailingslashit( $base );
		$seen  = array();
		try {
			if ( $quick && get_option( 'uploads_use_yearmonth_folders' ) ) {
				// ctime changes on every write and cannot be set back from PHP (unlike mtime).
				$since = $last_at ? $last_at - HOUR_IN_SECONDS : 0;
				foreach ( array( gmdate( 'Y/m' ), gmdate( 'Y/m', strtotime( 'first day of last month' ) ) ) as $ym ) {
					if ( ! is_dir( $base . '/' . $ym ) ) {
						continue;
					}
					foreach ( self::walk( $base, $ym ) as $rel ) {
						if ( ( microtime( true ) - $t0 ) > $budget ) {
							break 2;
						}
						$abs = $base . '/' . $rel;
						if ( $since && max( (int) @filemtime( $abs ), (int) @filectime( $abs ) ) < $since ) {
							continue;
						}
						$seen[ $rel ] = true;
						$found       += self::check_upload( $abs );
					}
				}
			}
			$cursor   = self::$stats['cursor'];
			$finished = true;
			foreach ( self::walk( $base, '', $cursor ) as $rel ) {
				if ( ( microtime( true ) - $t0 ) > $budget ) {
					$finished = false;
					break;
				}
				if ( ! isset( $seen[ $rel ] ) ) {
					$found += self::check_upload( $base . '/' . $rel );
				}
				self::$stats['cursor'] = $rel;
			}
			if ( $finished ) {
				self::$stats['cursor']       = '';
				self::$stats['full_pass_at'] = time();
			}
		} catch ( \Throwable $e ) {
			return $found;
		}
		return $found;
	}

	/**
	 * Files under $base/$sub in a stable depth-first order (sorted names). With $after,
	 * everything up to and including that path is skipped, whole folders at once.
	 *
	 * @return \Generator relative paths
	 */
	private static function walk( $base, $sub = '', $after = '' ) {
		$dir     = '' === $sub ? $base : $base . '/' . $sub;
		$entries = @scandir( $dir );
		if ( ! $entries ) {
			return;
		}
		foreach ( $entries as $name ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}
			$rel = '' === $sub ? $name : $sub . '/' . $name;
			$abs = $dir . '/' . $name;
			if ( is_dir( $abs ) && ! is_link( $abs ) ) {
				if ( in_array( $name, array( 'node_modules', '.git' ), true ) ) {
					continue;
				}
				// The cursor is past this folder and not inside it: skip it whole.
				if ( '' !== $after && self::path_cmp( $rel, $after ) < 0 && 0 !== strpos( $after, $rel . '/' ) ) {
					continue;
				}
				foreach ( self::walk( $base, $rel, $after ) as $r ) {
					yield $r;
				}
				continue;
			}
			if ( '' !== $after && self::path_cmp( $rel, $after ) <= 0 ) {
				continue;
			}
			yield $rel;
		}
	}

	/** Compare paths the way walk() visits them: folder by folder, names as scandir() sorts them. */
	private static function path_cmp( $a, $b ) {
		$x = explode( '/', $a );
		$y = explode( '/', $b );
		$n = min( count( $x ), count( $y ) );
		for ( $i = 0; $i < $n; $i++ ) {
			$c = strcmp( $x[ $i ], $y[ $i ] );
			if ( 0 !== $c ) {
				return $c;
			}
		}
		return count( $x ) <=> count( $y );
	}

	/** One file in uploads. @return int events recorded */
	private static function check_upload( $path ) {
		self::$stats['files_checked']++;
		$name = basename( $path );
		if ( 0 === strpos( $name, self::PROBE_PREFIX ) || ! is_file( $path ) ) {
			return 0;
		}
		if ( '.htaccess' === $name ) {
			return self::check_htaccess( $path );
		}
		if ( '.user.ini' === $name || 'php.ini' === $name ) {
			return self::report( $path, 'ini_in_uploads', 'high', __( 'PHP configuration file inside uploads. It can enable auto_prepend_file to run a payload on every request.', 'nightward' ) );
		}
		$exec  = Util::executable_extensions();
		$parts = explode( '.', strtolower( $name ) );
		$ext   = end( $parts );
		if ( in_array( $ext, $exec, true ) ) {
			if ( Util::is_inert_php( $path ) ) {
				return 0;
			}
			return self::report( $path, 'exec_in_uploads', 'high', __( 'Executable script in the uploads folder. Uploads should contain only media and documents; a script here can usually be run directly from the browser.', 'nightward' ) );
		}
		// shell.php.jpg - executed by some Apache setups (AddHandler).
		if ( count( $parts ) > 2 && array_intersect( array_slice( $parts, 1, -1 ), $exec ) ) {
			return self::report( $path, 'double_ext', 'medium', __( 'Double extension (e.g. file.php.jpg). On some Apache setups such files are executed as PHP.', 'nightward' ) );
		}
		if ( ! in_array( $ext, Util::media_extensions(), true ) ) {
			return 0;
		}
		$size = (int) @filesize( $path );
		if ( $size <= 0 ) {
			return 0;
		}
		$is_image = in_array( $ext, Util::image_extensions(), true );
		$scan     = Util::media_code_scan( $path, $size );
		if ( 'php' === $scan['hit'] ) {
			return self::report( $path, 'php_in_media', 'high', __( 'A media file contains PHP code. Used together with an include() elsewhere to hide a payload.', 'nightward' ), $scan['region'] );
		}
		if ( 'phar' === $scan['hit'] ) {
			return self::report( $path, 'phar_in_media', 'high', __( 'An image contains a PHAR archive stub. Passed to any file function as phar://, it can trigger object injection.', 'nightward' ), $scan['region'] );
		}
		// A .jpg holding a PNG or WebP is what optimisers and CDNs write - not a security issue.
		if ( $is_image && '' === Util::media_kind( $path ) ) {
			return self::report( $path, 'media_not_image', 'medium', __( 'The file has an image extension but its content is not an image. Payloads are stored like this and loaded with include() or eval(file_get_contents()) from another file.', 'nightward' ), (string) @file_get_contents( $path, false, null, 0, 512 * KB_IN_BYTES ) );
		}
		return 0;
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

	/** One finding per file: a file that keeps changing (a queue, a log) stays one record. */
	public static function event_key( $rel ) {
		return 'uploads|' . $rel;
	}

	/**
	 * Before 1.1.8 the key included the type and the file hash, so a changing file
	 * produced a new record on every change. Keep the newest record per file.
	 */
	public static function merge_legacy() {
		global $wpdb;
		if ( get_option( 'nightward_uploads_merged' ) || ! \Nightward\DB::ready() ) {
			return;
		}
		$t    = \Nightward\DB::events();
		$rows = $wpdb->get_results( "SELECT id, file, fingerprint, hits, status FROM {$t} WHERE module = 'uploads' ORDER BY last_seen DESC, id DESC" ); // phpcs:ignore
		$seen = array();
		$drop = array();
		foreach ( $rows as $r ) {
			if ( '' === (string) $r->file ) {
				continue;
			}
			if ( isset( $seen[ $r->file ] ) ) {
				$drop[]                        = (int) $r->id;
				$seen[ $r->file ]['hits']     += (int) $r->hits;
				continue;
			}
			$seen[ $r->file ] = array( 'id' => (int) $r->id, 'hits' => (int) $r->hits, 'fp' => $r->fingerprint );
		}
		foreach ( array_chunk( $drop, 200 ) as $chunk ) {
			$wpdb->query( "DELETE FROM {$t} WHERE id IN (" . implode( ',', $chunk ) . ')' ); // phpcs:ignore
		}
		foreach ( $seen as $file => $k ) {
			$fp = Events::fingerprint( self::event_key( $file ) );
			if ( $fp !== $k['fp'] ) {
				$wpdb->update( $t, array( 'fingerprint' => $fp, 'hits' => $k['hits'] ), array( 'id' => $k['id'] ) );
			}
		}
		update_option( 'nightward_uploads_merged', time(), false );
	}

	/**
	 * One record per file, but "Ignore" covers only the content you looked at: an ignored
	 * file whose content changed is reopened (and alerts like a new finding).
	 */
	private static function reopen_if_changed( $rel, $hash ) {
		global $wpdb;
		$t   = \Nightward\DB::events();
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT id, status, details FROM {$t} WHERE fingerprint = %s", Events::fingerprint( self::event_key( $rel ) ) ) ); // phpcs:ignore
		if ( ! $row || 'ignored' !== $row->status ) {
			return;
		}
		$d = json_decode( (string) $row->details, true );
		if ( $hash && ! empty( $d['md5'] ) && $d['md5'] !== $hash ) {
			Events::set_status( array( (int) $row->id ), 'resolved' ); // the upsert reopens resolved events as new
		}
	}

	private static function report( $path, $type, $sev, $why, $region = null ) {
		if ( null !== $region ) {
			// Media: indicators around the code that was found (it may sit at the end of a
			// 3 MB JPEG), plus the header rule on the file start.
			$ind = array_values( array_unique( array_merge( Integrity::payload_indicators_text( $region ), Integrity::payload_indicators( $path ) ) ) );
			// In a file that only pretends to be an image, a bare base64 blob is the payload itself.
			// Data URIs (an HTML page saved as .jpg embeds its images that way) are not a payload.
			$bare = preg_replace( '#data:[\w/+.\-]+;base64,[A-Za-z0-9+/=]+#', '', $region );
			if ( 'media_not_image' === $type && preg_match( '/[A-Za-z0-9+\/]{2000,}={0,2}/', $bare ) && ! in_array( 'long base64 blob', $ind, true ) ) {
				$ind[] = 'long base64 blob';
			}
		} else {
			$ind = Integrity::is_php( $path ) ? Integrity::payload_indicators( $path ) : array();
		}
		if ( $ind ) {
			$sev = 'critical';
		}
		$rel  = Attribution::rel( $path );
		$url  = content_url( substr( $rel, strlen( 'wp-content/' ) ) );
		$hash = (string) @md5_file( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		self::reopen_if_changed( $rel, $hash );
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
				'preview'     => substr( trim( preg_replace( array( '/[\x00-\x08\x0E-\x1F\x7F-\xFF]+/', '/\s+/' ), array( '·', ' ' ), substr( null !== $region ? $region : (string) @file_get_contents( $path, false, null, 0, 400 ), 0, 400 ) ) ), 0, 240 ),
				'url'         => $url,
				'md5'         => $hash,
			),
			'file'      => $rel,
			'key'       => self::event_key( $rel ),
		) );
		return 1;
	}
}
