<?php
/**
 * Who did it: maps a file, a backtrace or a hook callback to a component
 * (plugin:slug, theme:slug, mu:file, dropin:file, core) with file and line.
 */

namespace Nightward;

defined( 'ABSPATH' ) || exit;

class Attribution {

	private static $roots = null;
	private static $labels = null;

	private static function roots() {
		if ( null === self::$roots ) {
			self::$roots = array(
				'plugins' => trailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) ),
				'mu'      => trailingslashit( wp_normalize_path( WPMU_PLUGIN_DIR ) ),
				'themes'  => trailingslashit( wp_normalize_path( function_exists( 'get_theme_root' ) ? get_theme_root() : WP_CONTENT_DIR . '/themes' ) ),
				'content' => trailingslashit( wp_normalize_path( WP_CONTENT_DIR ) ),
				'abspath' => trailingslashit( wp_normalize_path( ABSPATH ) ),
				'self'    => trailingslashit( wp_normalize_path( NIGHTWARD_DIR ) ),
			);
		}
		return self::$roots;
	}

	/** Path relative to ABSPATH (or to wp-content's parent when wp-content is moved). */
	public static function rel( $file ) {
		$f = wp_normalize_path( (string) $file );
		$r = self::roots();
		if ( 0 === strpos( $f, $r['content'] ) ) {
			return 'wp-content/' . substr( $f, strlen( $r['content'] ) );
		}
		if ( 0 === strpos( $f, $r['abspath'] ) ) {
			return substr( $f, strlen( $r['abspath'] ) );
		}
		return $f;
	}

	public static function component_of_file( $file ) {
		$f = wp_normalize_path( (string) $file );
		if ( '' === $f ) {
			return 'unknown';
		}
		if ( false !== strpos( $f, "eval()'d code" ) ) {
			return 'eval';
		}
		$r = self::roots();
		if ( 0 === strpos( $f, $r['self'] ) ) {
			return 'nightward';
		}
		foreach ( array( 'plugins' => 'plugin', 'mu' => 'mu', 'themes' => 'theme' ) as $root => $kind ) {
			if ( 0 === strpos( $f, $r[ $root ] ) ) {
				$rest = substr( $f, strlen( $r[ $root ] ) );
				$seg  = strtok( $rest, '/' );
				if ( false === strpos( $rest, '/' ) && 'theme' !== $kind ) {
					$seg = preg_replace( '/\.php$/', '', $seg );
				}
				return $kind . ':' . $seg;
			}
		}
		if ( 0 === strpos( $f, $r['content'] ) ) {
			return 'dropin:' . substr( $f, strlen( $r['content'] ) );
		}
		if ( 0 === strpos( $f, $r['abspath'] . 'wp-includes/' ) || 0 === strpos( $f, $r['abspath'] . 'wp-admin/' ) ) {
			return 'core';
		}
		return 'other:' . basename( $f );
	}

	/**
	 * First stack frame that belongs to a plugin/theme/mu-plugin (not core, not us).
	 * Returns array( component, file, line ) — component 'core' when WordPress itself initiated.
	 */
	public static function caller( $depth = 40 ) {
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace
		$trace = debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS, $depth );
		$first_eval = null;
		foreach ( $trace as $fr ) {
			if ( empty( $fr['file'] ) ) {
				continue;
			}
			$c = self::component_of_file( $fr['file'] );
			if ( 'eval' === $c && ! $first_eval ) {
				$first_eval = $fr;
				continue;
			}
			if ( in_array( $c, array( 'core', 'nightward', 'unknown', 'eval' ), true ) || 0 === strpos( $c, 'other:' ) ) {
				continue;
			}
			return array(
				'component' => $c,
				'file'      => self::rel( $fr['file'] ),
				'line'      => isset( $fr['line'] ) ? (int) $fr['line'] : 0,
				'via_eval'  => (bool) $first_eval,
			);
		}
		if ( $first_eval ) {
			return array( 'component' => 'eval', 'file' => "eval()'d code", 'line' => (int) $first_eval['line'], 'via_eval' => true );
		}
		return array( 'component' => 'core', 'file' => '', 'line' => 0, 'via_eval' => false );
	}

	/** File/line/name of a hook callback via Reflection. */
	public static function callback_info( $cb ) {
		$out = array( 'name' => '?', 'file' => '', 'line' => 0, 'kind' => 'unknown', 'component' => 'unknown' );
		try {
			if ( is_string( $cb ) && false !== strpos( $cb, '::' ) ) {
				$cb = explode( '::', $cb, 2 );
			}
			if ( $cb instanceof \Closure ) {
				$rf          = new \ReflectionFunction( $cb );
				$out['kind'] = 'closure';
				$scope       = $rf->getClosureScopeClass();
				$out['name'] = '{closure}' . ( $scope ? ' in ' . $scope->getName() : '' );
			} elseif ( is_string( $cb ) ) {
				$rf          = new \ReflectionFunction( $cb );
				$out['kind'] = 'function';
				$out['name'] = $cb . '()';
			} elseif ( is_array( $cb ) && 2 === count( $cb ) ) {
				$cls         = is_object( $cb[0] ) ? get_class( $cb[0] ) : (string) $cb[0];
				$rf          = new \ReflectionMethod( $cls, $cb[1] );
				$out['kind'] = 'method';
				$out['name'] = $cls . '::' . $cb[1] . '()';
			} elseif ( is_object( $cb ) && method_exists( $cb, '__invoke' ) ) {
				$rf          = new \ReflectionMethod( $cb, '__invoke' );
				$out['kind'] = 'invokable';
				$out['name'] = get_class( $cb ) . '::__invoke()';
			} else {
				return $out;
			}
			$file             = (string) $rf->getFileName();
			$out['file']      = $file ? self::rel( $file ) : '(internal)';
			$out['line']      = (int) $rf->getStartLine();
			$out['component'] = $file ? self::component_of_file( $file ) : 'php';
			if ( $file && false !== strpos( $file, "eval()'d code" ) ) {
				$out['component'] = 'eval';
			}
		} catch ( \Throwable $e ) {
			$out['name'] = '(unresolvable callback)';
		}
		return $out;
	}

	/** Human label: plugin/theme name. Cheap enough for admin screens and reports only. */
	public static function label( $component ) {
		if ( null === self::$labels ) {
			self::$labels = array();
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			foreach ( get_plugins() as $file => $data ) {
				$slug = false === strpos( $file, '/' ) ? preg_replace( '/\.php$/', '', $file ) : strtok( $file, '/' );
				self::$labels[ 'plugin:' . $slug ] = $data['Name'];
			}
			foreach ( wp_get_themes() as $slug => $theme ) {
				self::$labels[ 'theme:' . $slug ] = $theme->get( 'Name' );
			}
		}
		if ( isset( self::$labels[ $component ] ) ) {
			return self::$labels[ $component ];
		}
		if ( 'core' === $component ) {
			return __( 'WordPress core', 'nightward' );
		}
		if ( 'eval' === $component ) {
			return __( 'code executed via eval()', 'nightward' );
		}
		if ( 0 === strpos( $component, 'mu:' ) ) {
			/* translators: %s: must-use plugin file name */
			return sprintf( __( 'must-use plugin %s', 'nightward' ), substr( $component, 3 ) );
		}
		if ( 0 === strpos( $component, 'dropin:' ) ) {
			/* translators: %s: drop-in file name */
			return sprintf( __( 'drop-in %s', 'nightward' ), substr( $component, 7 ) );
		}
		return $component;
	}

	/** Main file + header data of a plugin component (plugin:slug). */
	public static function plugin_data( $component ) {
		if ( 0 !== strpos( $component, 'plugin:' ) ) {
			return null;
		}
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$slug = substr( $component, 7 );
		foreach ( get_plugins() as $file => $data ) {
			$s = false === strpos( $file, '/' ) ? preg_replace( '/\.php$/', '', $file ) : strtok( $file, '/' );
			if ( $s === $slug ) {
				$data['_file'] = $file;
				return $data;
			}
		}
		return null;
	}

	/** Registrable domains a component legitimately talks to (from its header URIs). */
	public static function vendor_domains( $component ) {
		$data = self::plugin_data( $component );
		if ( ! $data && 0 === strpos( $component, 'theme:' ) ) {
			$t    = wp_get_theme( substr( $component, 6 ) );
			$data = array( 'PluginURI' => $t->get( 'ThemeURI' ), 'AuthorURI' => $t->get( 'AuthorURI' ), 'UpdateURI' => $t->get( 'UpdateURI' ) );
		}
		if ( ! $data ) {
			return array();
		}
		$out      = array();
		$platform = array( 'github.com', 'gitlab.com', 'wordpress.org', 'wordpress.com', 'codecanyon.net', 'themeforest.net', 'envato.com' );
		foreach ( array( 'PluginURI', 'AuthorURI', 'UpdateURI' ) as $k ) {
			$h = empty( $data[ $k ] ) ? '' : Util::host_of( $data[ $k ] );
			if ( $h && ! in_array( Util::registrable( $h ), $platform, true ) ) {
				$out[] = Util::registrable( $h );
			}
		}
		return array_values( array_unique( $out ) );
	}
}
