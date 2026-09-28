<?php
/**
 * File integrity.
 *
 * - WordPress core: official md5 checksums (api.wordpress.org).
 * - Plugins from WordPress.org: official per-version checksums
 *   (downloads.wordpress.org/plugin-checksums/{slug}/{version}.json).
 * - Everything else (premium plugins, themes): trust on first use. The first
 *   scan is the reference; later scans report files that changed while the
 *   version number stayed the same — updates change the version, injections
 *   don't.
 *
 * Runs in batches through WP-Cron (or AJAX from the dashboard) so it never
 * hits max_execution_time on shared hosting.
 */

namespace Nightward\Scanner;

use Nightward\Attribution;
use Nightward\DB;
use Nightward\Events;
use Nightward\Settings;
use Nightward\Util;
use Nightward\Monitor\Hooks_Watch;

defined( 'ABSPATH' ) || exit;

class Integrity {

	const JOB      = 'nightward_integrity_job';
	const LAST     = 'nightward_integrity_last';
	const VERSIONS = 'nightward_integrity_versions';
	const SKIP_DIRS = array( 'node_modules', '.git', '.svn', '.idea', '.cache' );

	public static function init_hooks() {
		add_action( 'upgrader_process_complete', array( __CLASS__, 'after_upgrade' ), 10, 2 );
		add_action( 'activated_plugin', array( __CLASS__, 'after_activation' ), 10, 1 );
		add_action( 'switch_theme', array( __CLASS__, 'after_theme_switch' ), 10, 0 );
	}

	/* ------------------------------------------------------------------ */
	/* Upgrade awareness                                                   */
	/* ------------------------------------------------------------------ */

	public static function after_upgrade( $upgrader, $extra ) {
		$components = array();
		$type       = isset( $extra['type'] ) ? $extra['type'] : '';
		if ( 'plugin' === $type ) {
			$list = ! empty( $extra['plugins'] ) ? (array) $extra['plugins'] : ( ! empty( $extra['plugin'] ) ? array( $extra['plugin'] ) : array() );
			if ( ! $list && isset( $upgrader->new_plugin_data ) && ! empty( $upgrader->result['destination_name'] ) ) {
				$list = array( $upgrader->result['destination_name'] . '/' );
			}
			foreach ( $list as $p ) {
				$components[] = 'plugin:' . ( false === strpos( $p, '/' ) ? preg_replace( '/\.php$/', '', $p ) : strtok( $p, '/' ) );
			}
		} elseif ( 'theme' === $type ) {
			$list = ! empty( $extra['themes'] ) ? (array) $extra['themes'] : ( ! empty( $extra['theme'] ) ? array( $extra['theme'] ) : array() );
			if ( ! $list && ! empty( $upgrader->result['destination_name'] ) ) {
				$list = array( $upgrader->result['destination_name'] );
			}
			foreach ( $list as $t ) {
				$components[] = 'theme:' . $t;
			}
		} elseif ( 'core' === $type ) {
			$components[] = 'core';
		}
		if ( $components ) {
			Hooks_Watch::mark_relearn( $components );
			$u = (array) get_option( 'nightward_upgraded', array() );
			foreach ( $components as $c ) {
				$u[ $c ] = time();
			}
			update_option( 'nightward_upgraded', $u, false );
		}
		if ( Settings::enabled( 'integrity' ) && ! wp_next_scheduled( 'nightward_integrity_start' ) ) {
			wp_schedule_single_event( time() + 120, 'nightward_integrity_start' );
		}
	}

	public static function after_activation( $plugin ) {
		Hooks_Watch::mark_relearn( array( 'plugin:' . ( false === strpos( $plugin, '/' ) ? preg_replace( '/\.php$/', '', $plugin ) : strtok( $plugin, '/' ) ) ) );
	}

	public static function after_theme_switch() {
		Hooks_Watch::mark_relearn( array( 'theme:' . get_stylesheet(), 'theme:' . get_template() ) );
	}

	/* ------------------------------------------------------------------ */
	/* Packages                                                            */
	/* ------------------------------------------------------------------ */

	/** @return array[] id, type, dir, version, name, slug */
	public static function packages() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$out   = array();
		$out[] = array( 'id' => 'core', 'type' => 'core', 'dir' => ABSPATH, 'version' => get_bloginfo( 'version' ), 'name' => 'WordPress', 'slug' => 'wordpress' );
		foreach ( get_plugins() as $file => $data ) {
			if ( false === strpos( $file, '/' ) ) {
				$slug = preg_replace( '/\.php$/', '', $file );
				$dir  = WP_PLUGIN_DIR . '/' . $file; // single-file plugin
			} else {
				$slug = strtok( $file, '/' );
				$dir  = WP_PLUGIN_DIR . '/' . $slug;
			}
			$out[] = array( 'id' => 'plugin:' . $slug, 'type' => 'plugin', 'dir' => $dir, 'version' => (string) $data['Version'], 'name' => $data['Name'], 'slug' => $slug, 'update_uri' => isset( $data['UpdateURI'] ) ? $data['UpdateURI'] : '' );
		}
		foreach ( wp_get_themes() as $slug => $theme ) {
			$out[] = array( 'id' => 'theme:' . $slug, 'type' => 'theme', 'dir' => $theme->get_stylesheet_directory(), 'version' => (string) $theme->get( 'Version' ), 'name' => $theme->get( 'Name' ), 'slug' => $slug );
		}
		return $out;
	}

	/** Relative (to package dir) paths of files to check, sorted. */
	public static function list_files( array $pkg ) {
		$dir = wp_normalize_path( $pkg['dir'] );
		if ( is_file( $dir ) ) {
			return array( basename( $dir ) );
		}
		if ( ! is_dir( $dir ) ) {
			return array();
		}
		$exts = Util::code_extensions();
		$out  = array();
		if ( 'core' === $pkg['type'] ) {
			// Core: root files + wp-admin + wp-includes. wp-content belongs to others.
			foreach ( (array) glob( trailingslashit( $dir ) . '*' ) as $f ) {
				if ( is_file( $f ) && self::is_code( $f, $exts ) ) {
					$out[] = basename( $f );
				}
			}
			foreach ( array( 'wp-admin', 'wp-includes' ) as $sub ) {
				$out = array_merge( $out, self::walk( trailingslashit( $dir ) . $sub, $sub . '/', $exts ) );
			}
		} else {
			$out = self::walk( $dir, '', $exts );
		}
		sort( $out, SORT_STRING );
		return $out;
	}

	private static function is_code( $f, $exts ) {
		$ext = strtolower( pathinfo( $f, PATHINFO_EXTENSION ) );
		return in_array( $ext, $exts, true ) || '.htaccess' === basename( $f ) || '.user.ini' === basename( $f );
	}

	private static function walk( $dir, $prefix, $exts ) {
		$out = array();
		if ( ! is_dir( $dir ) ) {
			return $out;
		}
		try {
			$it = new \RecursiveIteratorIterator(
				new \RecursiveCallbackFilterIterator(
					new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
					function ( $cur ) {
						return ! ( $cur->isDir() && in_array( $cur->getFilename(), self::SKIP_DIRS, true ) );
					}
				)
			);
			$base = strlen( trailingslashit( wp_normalize_path( $dir ) ) );
			foreach ( $it as $f ) {
				if ( $f->isFile() && self::is_code( $f->getPathname(), $exts ) ) {
					$out[] = $prefix . substr( wp_normalize_path( $f->getPathname() ), $base );
					if ( count( $out ) > 40000 ) {
						break;
					}
				}
			}
		} catch ( \Throwable $e ) {
			return $out;
		}
		return $out;
	}

	/* ------------------------------------------------------------------ */
	/* Reference checksums                                                 */
	/* ------------------------------------------------------------------ */

	/** @return array|null relpath => md5, or null when unavailable. */
	public static function core_checksums() {
		$ver    = get_bloginfo( 'version' );
		$locale = get_locale();
		$key    = 'nightward_cs_core_' . md5( $ver . $locale );
		$cached = get_transient( $key );
		if ( false !== $cached ) {
			return is_array( $cached ) ? $cached : null;
		}
		// Свій запит замість get_core_checksums(): той кидає PHP warning, коли API недоступний.
		$cs = null;
		foreach ( array_unique( array( $locale, 'en_US' ) ) as $loc ) {
			$res = wp_remote_get( 'https://api.wordpress.org/core/checksums/1.0/?' . http_build_query( array( 'version' => $ver, 'locale' => $loc ) ), array( 'timeout' => 15, 'headers' => array( 'X-Nightward-Probe' => '1' ) ) );
			if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
				continue;
			}
			$j = json_decode( wp_remote_retrieve_body( $res ), true );
			if ( ! empty( $j['checksums'] ) && is_array( $j['checksums'] ) ) {
				$cs = $j['checksums'];
				break;
			}
		}
		set_transient( $key, $cs ? $cs : 'none', $cs ? WEEK_IN_SECONDS : 6 * HOUR_IN_SECONDS );
		return $cs ? $cs : null;
	}

	/** @return array|null relpath => array( md5 => [], sha256 => [] ), null when not a wp.org plugin. */
	public static function plugin_checksums( $slug, $version ) {
		$key    = 'nightward_cs_p_' . md5( $slug . '|' . $version );
		$cached = get_transient( $key );
		if ( false !== $cached ) {
			return is_array( $cached ) ? $cached : null;
		}
		$url = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
		$res = wp_remote_get( $url, array( 'timeout' => 15, 'headers' => array( 'X-Nightward-Probe' => '1' ) ) );
		$out = null;
		if ( ! is_wp_error( $res ) && 200 === (int) wp_remote_retrieve_response_code( $res ) ) {
			$j = json_decode( wp_remote_retrieve_body( $res ), true );
			if ( ! empty( $j['files'] ) && is_array( $j['files'] ) ) {
				$out = array();
				foreach ( $j['files'] as $path => $h ) {
					$out[ $path ] = array(
						'md5'    => isset( $h['md5'] ) ? (array) $h['md5'] : array(),
						'sha256' => isset( $h['sha256'] ) ? (array) $h['sha256'] : array(),
					);
				}
			}
		}
		$transient_error = is_wp_error( $res ) || (int) wp_remote_retrieve_response_code( $res ) >= 500;
		set_transient( $key, $out ? $out : 'none', $out ? MONTH_IN_SECONDS : ( $transient_error ? HOUR_IN_SECONDS : WEEK_IN_SECONDS ) );
		return $out;
	}

	/* ------------------------------------------------------------------ */
	/* Job                                                                 */
	/* ------------------------------------------------------------------ */

	public static function start( $manual = false ) {
		if ( ! Settings::enabled( 'integrity' ) && ! $manual ) {
			return;
		}
		$job = get_option( self::JOB );
		if ( is_array( $job ) && empty( $job['done'] ) && time() - (int) $job['touched'] < 15 * MINUTE_IN_SECONDS ) {
			return; // вже йде
		}
		$pkgs = array();
		foreach ( self::packages() as $p ) {
			$pkgs[] = $p['id'];
		}
		update_option( self::JOB, array(
			'started'  => time(),
			'touched'  => time(),
			'queue'    => $pkgs,
			'total'    => count( $pkgs ),
			'offset'   => 0,
			'files'    => 0,
			'problems' => 0,
			'verified' => array(), // package => core|wporg|tofu|baseline
			'done'     => false,
			'manual'   => (bool) $manual,
		), false );
		if ( ! $manual ) {
			self::schedule_step();
		}
	}

	private static function schedule_step() {
		if ( ! wp_next_scheduled( 'nightward_integrity_step' ) ) {
			wp_schedule_single_event( time(), 'nightward_integrity_step' );
		}
	}

	/** One batch. Returns progress for the AJAX runner. */
	public static function step( $budget = 20 ) {
		$job = get_option( self::JOB );
		if ( ! is_array( $job ) || ! empty( $job['done'] ) ) {
			return self::status();
		}
		$t0    = microtime( true );
		$batch = (int) Settings::get( 'integrity_batch', 400 );
		$index = array();
		foreach ( self::packages() as $p ) {
			$index[ $p['id'] ] = $p;
		}
		$processed = 0;
		while ( $job['queue'] && $processed < $batch && ( microtime( true ) - $t0 ) < $budget ) {
			$id = $job['queue'][0];
			if ( ! isset( $index[ $id ] ) ) {
				array_shift( $job['queue'] );
				$job['offset'] = 0;
				continue;
			}
			$res = self::scan_package( $index[ $id ], $job['offset'], $batch - $processed, $t0, $budget );
			$processed      += $res['processed'];
			$job['files']   += $res['processed'];
			$job['problems'] += $res['problems'];
			$job['verified'][ $id ] = $res['mode'];
			if ( $res['finished'] ) {
				array_shift( $job['queue'] );
				$job['offset'] = 0;
			} else {
				$job['offset'] = $res['next_offset'];
			}
		}
		$job['touched'] = time();
		if ( ! $job['queue'] ) {
			$job['done'] = true;
			update_option( self::LAST, array(
				'finished' => time(),
				'started'  => $job['started'],
				'files'    => $job['files'],
				'problems' => $job['problems'],
				'verified' => $job['verified'],
			), false );
		}
		update_option( self::JOB, $job, false );
		if ( ! $job['done'] && empty( $job['manual'] ) ) {
			self::schedule_step();
			if ( function_exists( 'spawn_cron' ) && ! wp_doing_cron() ) {
				spawn_cron();
			}
		}
		return self::status();
	}

	public static function status() {
		$job  = get_option( self::JOB );
		$last = get_option( self::LAST );
		return array(
			'running'  => is_array( $job ) && empty( $job['done'] ),
			'done'     => is_array( $job ) ? count( $job['verified'] ) : 0,
			'total'    => is_array( $job ) ? $job['total'] : 0,
			'files'    => is_array( $job ) ? $job['files'] : 0,
			'problems' => is_array( $job ) ? $job['problems'] : 0,
			'current'  => is_array( $job ) && $job['queue'] ? $job['queue'][0] : '',
			'last'     => is_array( $last ) ? $last : null,
		);
	}

	/* ------------------------------------------------------------------ */
	/* Scan one package (resumable)                                        */
	/* ------------------------------------------------------------------ */

	private static function scan_package( array $pkg, $offset, $limit, $t0, $budget ) {
		global $wpdb;
		$files    = self::list_files( $pkg );
		$versions = (array) get_option( self::VERSIONS, array() );
		$prev_ver = isset( $versions[ $pkg['id'] ] ) ? $versions[ $pkg['id'] ] : null;
		$ref      = null;
		$mode     = 'tofu';

		if ( 'core' === $pkg['type'] ) {
			$ref  = self::core_checksums();
			$mode = $ref ? 'core' : 'tofu';
		} elseif ( 'plugin' === $pkg['type'] && ! self::has_foreign_update_uri( $pkg ) ) {
			$ref = self::plugin_checksums( $pkg['slug'], $pkg['version'] );
			if ( $ref ) {
				// Той самий slug, але інший продукт (преміум-версія з назвою безкоштовної) — тоді TOFU.
				$php  = array_filter( $files, array( __CLASS__, 'is_php' ) );
				$hit  = count( array_intersect( $php, array_keys( $ref ) ) );
				$ref  = $php && $hit / count( $php ) < 0.5 ? null : $ref;
			}
			$mode = $ref ? 'wporg' : 'tofu';
		}

		// Версія змінилась — легітимне оновлення (або ручне): старий еталон більше не діє.
		$rebaseline = 'tofu' === $mode && null !== $prev_ver && $prev_ver !== $pkg['version'];
		$first_time = 'tofu' === $mode && null === $prev_ver;
		if ( 0 === $offset && $rebaseline ) {
			$upgraded = (array) get_option( 'nightward_upgraded', array() );
			if ( empty( $upgraded[ $pkg['id'] ] ) || time() - $upgraded[ $pkg['id'] ] > 2 * DAY_IN_SECONDS ) {
				Events::record( array(
					'module'    => 'integrity',
					'type'      => 'manual_update',
					'severity'  => 'low',
					/* translators: 1: name, 2: old version, 3: new version */
					'title'     => array( __( '%1$s changed version %2$s → %3$s outside the WordPress updater', 'nightward' ), $pkg['name'], $prev_ver, $pkg['version'] ),
					'details'   => array( 'explanation' => __( 'Files were replaced via FTP, SSH, a deployment or a third-party manager. If none of that was you, compare the package with the vendor\'s copy.', 'nightward' ) ),
					'component' => $pkg['id'],
					'key'       => 'integrity|manualupd|' . $pkg['id'] . '|' . $pkg['version'],
				) );
			}
			$wpdb->delete( DB::files(), array( 'package' => $pkg['id'] ) );
		}

		$known = array();
		if ( 'tofu' === $mode && ! $first_time && ! $rebaseline ) {
			foreach ( $wpdb->get_results( $wpdb->prepare( 'SELECT path, hash FROM ' . DB::files() . ' WHERE package = %s', $pkg['id'] ) ) as $r ) { // phpcs:ignore
				$known[ $r->path ] = $r->hash;
			}
		}
		$has_baseline = (bool) $known;
		$base_dir     = trailingslashit( is_file( $pkg['dir'] ) ? dirname( $pkg['dir'] ) : $pkg['dir'] );
		$prefix       = 'core' === $pkg['type'] ? '' : Attribution::rel( $base_dir );
		$problems     = 0;
		$processed    = 0;
		$n            = count( $files );
		$now          = Util::now();

		for ( $i = $offset; $i < $n && $processed < $limit; $i++ ) {
			if ( $processed && ( microtime( true ) - $t0 ) > $budget ) {
				break;
			}
			$rel  = $files[ $i ];
			$abs  = $base_dir . $rel;
			$show = ( 'core' === $pkg['type'] ? '' : $prefix ) . $rel;
			$processed++;

			if ( 'core' === $mode ) {
				if ( isset( $ref[ $rel ] ) ) {
					if ( md5_file( $abs ) !== $ref[ $rel ] ) {
						$problems += self::report_file( $pkg, $show, $abs, 'modified', __( 'Core file differs from the official WordPress release.', 'nightward' ), 'high' );
					} else {
						Events::resolve_by( 'integrity', 'modified', $show );
					}
				} elseif ( 0 === strpos( $rel, 'wp-admin/' ) || 0 === strpos( $rel, 'wp-includes/' ) || preg_match( '/\.php$/', $rel ) ) {
					if ( ! self::core_extra_ok( $rel ) ) {
						$problems += self::report_file( $pkg, $show, $abs, 'unknown_file', __( 'File is not part of WordPress but sits among core files. Malware hides here because nobody looks.', 'nightward' ), 'high' );
					}
				}
				continue;
			}

			if ( 'wporg' === $mode ) {
				if ( isset( $ref[ $rel ] ) ) {
					$ok = ( $ref[ $rel ]['sha256'] && in_array( hash_file( 'sha256', $abs ), $ref[ $rel ]['sha256'], true ) )
						|| ( ! $ref[ $rel ]['sha256'] && in_array( md5_file( $abs ), $ref[ $rel ]['md5'], true ) );
					if ( ! $ok ) {
						$problems += self::report_file( $pkg, $show, $abs, 'modified', __( 'File differs from the official WordPress.org copy of this exact version.', 'nightward' ), 'high' );
					} else {
						Events::resolve_by( 'integrity', 'modified', $show );
					}
				} elseif ( self::is_php( $rel ) ) {
					$problems += self::report_file( $pkg, $show, $abs, 'unknown_file', __( 'PHP file that is not in the official WordPress.org release of this version.', 'nightward' ), 'high' );
				}
				continue;
			}

			// TOFU
			$hash = hash_file( 'sha256', $abs );
			if ( ! $has_baseline ) {
				$wpdb->replace( DB::files(), array( 'path_key' => sha1( $show ), 'path' => $show, 'package' => $pkg['id'], 'hash' => $hash, 'size' => (int) @filesize( $abs ), 'source' => 'tofu', 'seen_at' => $now ) );
				continue;
			}
			if ( ! isset( $known[ $show ] ) ) {
				if ( self::is_php( $rel ) ) {
					$problems += self::report_file( $pkg, $show, $abs, 'new_file', __( 'New PHP file appeared although the version number did not change.', 'nightward' ), 'high', $hash );
				}
				continue;
			}
			if ( $known[ $show ] !== $hash ) {
				$problems += self::report_file( $pkg, $show, $abs, 'modified', __( 'File changed although the version number did not change. Updates change the version; injected code does not.', 'nightward' ), 'high', $hash );
			} else {
				Events::resolve_by( 'integrity', 'modified', $show );
			}
		}

		$finished = $i >= $n;
		if ( $finished ) {
			$versions[ $pkg['id'] ] = $pkg['version'];
			update_option( self::VERSIONS, $versions, false );
			if ( 'tofu' === $mode && ! $has_baseline && $n && null === $prev_ver && ! Settings::in_learning() && 'core' !== $pkg['type'] ) {
				Events::record( array(
					'module'    => 'integrity',
					'type'      => 'baseline',
					'severity'  => 'info',
					/* translators: 1: name, 2: version, 3: files */
					'title'     => array( __( 'Reference snapshot taken for %1$s %2$s (%3$d files)', 'nightward' ), $pkg['name'], $pkg['version'], $n ),
					'details'   => array( 'explanation' => __( 'This package is not on WordPress.org, so its current files become the reference. Nightward cannot tell whether they were clean at this moment.', 'nightward' ) ),
					'component' => $pkg['id'],
					'key'       => 'integrity|baseline|' . $pkg['id'] . '|' . $pkg['version'],
				) );
			}
			// Missing files (TOFU): known but gone.
			if ( 'tofu' === $mode && $has_baseline ) {
				$present = array_flip( array_map( function ( $r ) use ( $prefix, $pkg ) {
					return ( 'core' === $pkg['type'] ? '' : $prefix ) . $r;
				}, $files ) );
				$gone = array_diff_key( $known, $present );
				if ( $gone ) {
					Events::record( array(
						'module'    => 'integrity',
						'type'      => 'missing',
						'severity'  => 'low',
						/* translators: 1: count, 2: name */
						'title'     => array( __( '%1$d files removed from %2$s without a version change', 'nightward' ), count( $gone ), $pkg['name'] ),
						'details'   => array( 'files' => array_slice( array_keys( $gone ), 0, 30 ) ),
						'component' => $pkg['id'],
						'key'       => 'integrity|missing|' . $pkg['id'] . '|' . md5( implode( ',', array_keys( $gone ) ) ),
					) );
				}
			}
		}
		return array( 'processed' => $processed, 'problems' => $problems, 'finished' => $finished, 'next_offset' => $i, 'mode' => $has_baseline || 'tofu' !== $mode ? $mode : 'baseline' );
	}

	private static function has_foreign_update_uri( array $pkg ) {
		if ( empty( $pkg['update_uri'] ) ) {
			return false;
		}
		$h = Util::host_of( $pkg['update_uri'] );
		return $h && ! in_array( $h, array( 'wordpress.org', 'w.org' ), true );
	}

	public static function is_php( $rel ) {
		return (bool) preg_match( '/\.(php\d?|phtml|phar|pht|inc)$/i', $rel );
	}

	/** Extra files in core dirs that are harmless and common. */
	private static function core_extra_ok( $rel ) {
		$ok = array( 'wp-config.php', 'wp-config-sample.php', '.htaccess', '.user.ini', 'php.ini', '.maintenance', 'wp-cli.yml', 'wordfence-waf.php', 'object-cache.php', 'robots.txt', 'favicon.ico', 'error_log', 'wp-config-local.php' );
		if ( in_array( $rel, $ok, true ) ) {
			return true;
		}
		// Verification files from Google/Bing/Yandex etc. are HTML/TXT, not code.
		return ! self::is_php( $rel ) && false === strpos( $rel, '/' ) && ! in_array( strtolower( pathinfo( $rel, PATHINFO_EXTENSION ) ), array( 'php', 'js', 'htaccess' ), true );
	}

	/** Markers that make a changed file much more likely to be malicious. */
	public static function payload_indicators( $abs ) {
		$code = (string) @file_get_contents( $abs, false, null, 0, 512 * 1024 );
		$hits = array();
		$rules = array(
			'eval(base64/gz)'        => '/eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin)\s*\(/i',
			'input → code'           => '/(eval|assert|system|exec|passthru|shell_exec|popen|proc_open|create_function)\s*\(\s*(stripslashes\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER)/i',
			'variable function call from request' => '/\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(/i',
			'preg_replace /e'        => '/preg_replace\s*\(\s*[\'"](.).*\1[a-z]*e[a-z]*[\'"]\s*,/i',
			'long base64 blob'       => '/[\'"][A-Za-z0-9+\/]{2000,}={0,2}[\'"]/',
			'obfuscated chr() chain' => '/(chr\s*\(\s*\d+\s*\)\s*\.\s*){12,}/i',
			'writes PHP files'       => '/(file_put_contents|fwrite)\s*\([^;]{0,200}\.php[\'"]/i',
			'hidden in image header' => '/^\s*(GIF8|\x89PNG|\xFF\xD8\xFF)[\s\S]{0,400}<\?php/',
			'remote include'         => '/(include|require)(_once)?\s*\(?\s*[\'"]https?:\/\//i',
		);
		foreach ( $rules as $name => $rx ) {
			if ( preg_match( $rx, $code ) ) {
				$hits[] = $name;
			}
		}
		return $hits;
	}

	private static function report_file( array $pkg, $show, $abs, $type, $why, $sev, $hash = '' ) {
		$ind = self::is_php( $show ) ? self::payload_indicators( $abs ) : array();
		if ( $ind ) {
			$sev = 'critical';
		}
		Events::record( array(
			'module'    => 'integrity',
			'type'      => $type,
			'severity'  => $sev,
			/* translators: 1: file, 2: package name */
			'title'     => array( 'new_file' === $type || 'unknown_file' === $type ? __( 'Unexpected file %1$s in %2$s', 'nightward' ) : __( 'Modified file %1$s in %2$s', 'nightward' ), $show, $pkg['name'] ),
			'details'   => array(
				'explanation' => $why,
				'package'     => $pkg['name'] . ' ' . $pkg['version'],
				'size'        => Util::human_bytes( (int) @filesize( $abs ) ),
				'modified'    => wp_date( 'Y-m-d H:i', (int) @filemtime( $abs ) ),
				'indicators'  => $ind,
			),
			'component' => $pkg['id'],
			'file'      => $show,
			'key'       => 'integrity|' . $type . '|' . $show . '|' . ( $hash ? $hash : md5_file( $abs ) ),
		) );
		return 1;
	}

	/** Admin action: accept the current state of a package as the new reference. */
	public static function accept( $package_id ) {
		global $wpdb;
		$wpdb->delete( DB::files(), array( 'package' => $package_id ) );
		$v = (array) get_option( self::VERSIONS, array() );
		unset( $v[ $package_id ] );
		update_option( self::VERSIONS, $v, false );
		foreach ( self::packages() as $p ) {
			if ( $p['id'] === $package_id ) {
				$v[ $package_id ] = $p['version'];
				update_option( self::VERSIONS, $v, false );
				$files  = self::list_files( $p );
				$base   = trailingslashit( is_file( $p['dir'] ) ? dirname( $p['dir'] ) : $p['dir'] );
				$prefix = 'core' === $p['type'] ? '' : Attribution::rel( $base );
				foreach ( $files as $rel ) {
					$show = $prefix . $rel;
					$wpdb->replace( DB::files(), array( 'path_key' => sha1( $show ), 'path' => $show, 'package' => $package_id, 'hash' => hash_file( 'sha256', $base . $rel ), 'size' => (int) @filesize( $base . $rel ), 'source' => 'tofu', 'seen_at' => Util::now() ) );
				}
			}
		}
		$t = DB::events();
		$wpdb->query( $wpdb->prepare( "UPDATE {$t} SET status = 'resolved' WHERE module = 'integrity' AND component = %s AND status IN ('open','acknowledged')", $package_id ) ); // phpcs:ignore
	}
}
