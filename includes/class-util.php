<?php
/**
 * Small helpers shared by monitors, scanners and reports.
 */

namespace Nightward;

defined( 'ABSPATH' ) || exit;

class Util {

	/** Second-level registrable domain, aware of common two-part TLDs. */
	public static function registrable( $host ) {
		$host  = strtolower( trim( (string) $host, '.' ) );
		$parts = explode( '.', $host );
		$n     = count( $parts );
		if ( $n < 2 || filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return $host;
		}
		$two = $parts[ $n - 2 ] . '.' . $parts[ $n - 1 ];
		$multi = array( 'co.uk', 'org.uk', 'ac.uk', 'com.au', 'net.au', 'com.ua', 'in.ua', 'org.ua', 'kiev.ua', 'co.jp',
			'com.br', 'com.tr', 'co.in', 'co.za', 'com.mx', 'com.pl', 'com.cn', 'co.nz', 'com.sg', 'co.il', 'com.ar',
			'com.es', 'co.id' );
		if ( $n >= 3 && in_array( $two, $multi, true ) ) {
			return $parts[ $n - 3 ] . '.' . $two;
		}
		return $two;
	}

	public static function host_of( $url ) {
		$h = wp_parse_url( (string) $url, PHP_URL_HOST );
		return $h ? strtolower( $h ) : '';
	}

	public static function is_public_ip_literal( $host ) {
		return (bool) filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	public static function is_own_host( $host ) {
		$own = array( self::host_of( home_url() ), self::host_of( site_url() ), 'localhost', '127.0.0.1', '::1' );
		return in_array( strtolower( $host ), array_filter( $own ), true );
	}

	/**
	 * Hosts that are well-known infrastructure. Everything else is shown to the
	 * admin once so they can decide.
	 */
	public static function infra_hosts() {
		return array(
			'wordpress.org', 'w.org', 'wordpress.com', 'wp.com', 'gravatar.com', 'github.com', 'githubusercontent.com',
			'googleapis.com', 'gstatic.com', 'google.com', 'recaptcha.net', 'cloudflare.com', 'jsdelivr.net',
			'unpkg.com', 'cdnjs.com', 'youtube.com', 'vimeo.com', 'stripe.com', 'paypal.com', 'amazonaws.com',
			'microsoft.com', 'apple.com', 'facebook.com', 'openai.com', 'anthropic.com', 'mailchimp.com',
			'sendgrid.net', 'mailgun.net', 'freemius.com', 'envato.com', 'woocommerce.com', 'woo.com',
		);
	}

	/** Hosts that should never appear in a normal plugin's outbound traffic. */
	public static function bad_host_reason( $host ) {
		$host = strtolower( $host );
		$rules = array(
			'/(^|\.)pastebin\.com$|(^|\.)paste\.ee$|hastebin\.com$|ghostbin\.|termbin\.com$|transfer\.sh$|(^|\.)file\.io$|anonfiles\.com$/'
				=> __( 'paste / anonymous file-sharing service', 'nightward' ),
			'/\.ngrok(-free)?\.(io|app|dev)$|\.trycloudflare\.com$|\.loca\.lt$|\.localtunnel\.me$|\.serveo\.net$|\.bore\.pub$/'
				=> __( 'tunnel service (ngrok, Cloudflare tunnel…)', 'nightward' ),
			'/(^|\.)webhook\.site$|requestbin|pipedream\.net$/'
				=> __( 'request-capture service', 'nightward' ),
			'/\.(no-ip|ddns|duckdns|hopto|zapto|myftp|redirectme|sytes|bounceme)\.(org|net|com|info|biz)$/'
				=> __( 'dynamic DNS domain', 'nightward' ),
			'/\.onion$/' => __( 'TOR hidden service', 'nightward' ),
			'/(^|\.)(polyfill\.io|bootcss\.com|bootcdn\.net|staticfile\.org|polyfill\.com)$/'
				=> __( 'domain from the polyfill.io supply-chain attack', 'nightward' ),
			'/(gpltimes|gplvault|festinger|babiato|nulled|wplocker|gplpalace|weadown)/'
				=> __( 'distributor of pirated (nulled) plugins', 'nightward' ),
		);
		foreach ( $rules as $rx => $why ) {
			if ( preg_match( $rx, $host ) ) {
				return $why;
			}
		}
		return '';
	}

	/** Sensitive request paths: telegram bot API, discord webhooks go to normal hosts. */
	public static function bad_url_reason( $url ) {
		if ( preg_match( '#api\.telegram\.org/bot#i', $url ) ) {
			return __( 'Telegram bot API (common exfiltration channel)', 'nightward' );
		}
		if ( preg_match( '#discord(app)?\.com/api/webhooks#i', $url ) ) {
			return __( 'Discord webhook (common exfiltration channel)', 'nightward' );
		}
		return '';
	}

	/** URL without query values: keys stay, values (keys, tokens, domains) are dropped. */
	public static function redact_url( $url ) {
		$url = Redact::url( (string) $url ); // credentials in the path and user:pass@ go first
		$p   = wp_parse_url( $url );
		if ( ! $p || empty( $p['host'] ) ) {
			return substr( (string) $url, 0, 200 );
		}
		$out = ( isset( $p['scheme'] ) ? $p['scheme'] : 'http' ) . '://' . $p['host']
			. ( isset( $p['port'] ) ? ':' . $p['port'] : '' ) . ( isset( $p['path'] ) ? $p['path'] : '/' );
		if ( ! empty( $p['query'] ) ) {
			parse_str( $p['query'], $q );
			$out .= '?' . implode( '&', array_map( function ( $k ) {
				return $k . '=…';
			}, array_keys( (array) $q ) ) );
		}
		return substr( $out, 0, 300 );
	}

	/**
	 * A lock that holds across parallel requests. add_option() is not one: it upserts
	 * (INSERT ... ON DUPLICATE KEY UPDATE) and trusts the per-request "notoptions"
	 * cache, so two requests could both "add" it and both send the daily report.
	 * Here the database decides: INSERT IGNORE succeeds for exactly one request; a lock
	 * older than $ttl is taken over with a compare-and-swap UPDATE.
	 */
	public static function lock( $name, $ttl ) {
		global $wpdb;
		$now = time();
		$got = (int) $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $name, (string) $now ) ); // phpcs:ignore
		if ( ! $got ) {
			$old = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $name ) ); // phpcs:ignore
			if ( null === $old || (int) $old > $now - $ttl ) {
				return false;
			}
			$got = (int) $wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND option_value = %s", (string) $now, $name, $old ) ); // phpcs:ignore
		}
		self::forget_option_cache( $name );
		return $got > 0;
	}

	public static function unlock( $name ) {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s", $name ) ); // phpcs:ignore
		self::forget_option_cache( $name );
	}

	/** Read an option straight from the database (another request may have just changed it). */
	public static function fresh_option( $name, $default = false ) {
		global $wpdb;
		$v = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $name ) ); // phpcs:ignore
		return null === $v ? $default : maybe_unserialize( $v );
	}

	private static function forget_option_cache( $name ) {
		wp_cache_delete( $name, 'options' );
		$no = wp_cache_get( 'notoptions', 'options' );
		if ( is_array( $no ) && isset( $no[ $name ] ) ) {
			unset( $no[ $name ] );
			wp_cache_set( 'notoptions', $no, 'options' );
		}
	}

	public static function now() {
		return current_time( 'mysql', true );
	}

	public static function human_bytes( $b ) {
		$u = array( 'B', 'KB', 'MB', 'GB' );
		$i = 0;
		while ( $b >= 1024 && $i < 3 ) {
			$b /= 1024;
			$i++;
		}
		return ( $i ? number_format_i18n( $b, 1 ) : (int) $b ) . ' ' . $u[ $i ];
	}

	/** "2 hours ago" from a GMT mysql datetime. */
	public static function ago( $gmt ) {
		if ( ! $gmt ) {
			return '—';
		}
		$ts = strtotime( $gmt . ' UTC' );
		/* translators: %s: human time difference, e.g. "5 mins" */
		return sprintf( __( '%s ago', 'nightward' ), human_time_diff( $ts, time() ) );
	}

	public static function local_time( $gmt, $format = null ) {
		if ( ! $gmt ) {
			return '—';
		}
		$format = $format ? $format : get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		return wp_date( $format, strtotime( $gmt . ' UTC' ) );
	}

	public static function is_admin_ui_request() {
		return is_admin() && ! wp_doing_ajax() && ! wp_doing_cron();
	}

	public static function request_context() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'cli';
		}
		if ( wp_doing_cron() ) {
			return 'cron';
		}
		if ( wp_doing_ajax() ) {
			return 'ajax';
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'rest';
		}
		if ( ! empty( $_SERVER['REQUEST_URI'] ) && false !== strpos( (string) $_SERVER['REQUEST_URI'], '/wp-json/' ) ) {
			return 'rest';
		}
		return is_admin() ? 'admin' : 'frontend';
	}

	public static function request_path() {
		// Not sanitize_text_field(): it deletes percent-encoded bytes (plugin=a%2Fb.php became "ab.php").
		return isset( $_SERVER['REQUEST_URI'] ) ? substr( preg_replace( '/[\x00-\x20\x7F<>"\'`\\\\]/', '', wp_unslash( (string) $_SERVER['REQUEST_URI'] ) ), 0, 200 ) : ''; // phpcs:ignore
	}

	public static function client_ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}

	/** Files the admin may upload/edit through normal means don't need to be scanned; this list is for code. */
	public static function code_extensions() {
		return array( 'php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7', 'php8', 'pht', 'phps', 'inc', 'js', 'mjs', 'htaccess', 'ini', 'twig', 'json' );
	}

	public static function executable_extensions() {
		return array( 'php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7', 'php8', 'pht', 'phps', 'shtml', 'cgi', 'pl' );
	}

	/** Silence-is-golden stubs and guarded datastores (`<?php exit; ?>` + data) are not executable payload. */
	public static function is_inert_php( $path ) {
		$size = @filesize( $path );
		if ( false === $size ) {
			return false;
		}
		$head = (string) @file_get_contents( $path, false, null, 0, 600 );
		if ( $size < 400 && preg_match( '#^\s*(<\?php)?\s*((//|\#)[^\n]*\n|/\*.*?\*/|\s|(defined\s*\(\s*[\'"]ABSPATH[\'"]\s*\)\s*(\|\||or)\s*)?(exit|die)\s*(\(\s*\d*\s*\))?\s*;|\?>)*\s*$#si', $head ) ) {
			return true;
		}
		// Sucuri, Wordfence, cache plugins: a data file whose first statement is exit,
		// optionally after comments (Sucuri: "// datastore=…;" "// created_on=…;").
		// Nothing after it can ever run - whatever the data contains, even "<?".
		return (bool) preg_match( '#^(\xEF\xBB\xBF)?\s*<\?php(\s|/\*.*?\*/|//[^\n]*\n|\#[^\n]*\n)*(exit|die)\s*(\(\s*(\d+|\'[^\'()$]*\'|"[^"()$]*")?\s*\))?\s*;#is', $head );
	}

	/* ------------------------------------------------------------------ */
	/* Media files                                                         */
	/* ------------------------------------------------------------------ */

	/** Extensions whose content is checked for code. */
	public static function media_extensions() {
		return array( 'jpg', 'jpeg', 'jpe', 'png', 'gif', 'webp', 'avif', 'heic', 'heif', 'ico', 'bmp', 'tif', 'tiff', 'svg', 'txt' );
	}

	/** Media extensions that promise a binary image with a signature (not svg / txt). */
	public static function image_extensions() {
		return array_values( array_diff( self::media_extensions(), array( 'svg', 'txt' ) ) );
	}

	/** What the first bytes say the file is: jpeg, png, gif, webp, avif, heic, ico, bmp, tiff or ''. */
	public static function media_kind( $path ) {
		$h = (string) @file_get_contents( $path, false, null, 0, 32 );
		if ( strlen( $h ) < 4 ) {
			return '';
		}
		if ( 0 === strncmp( $h, "\xFF\xD8\xFF", 3 ) ) {
			return 'jpeg';
		}
		if ( 0 === strncmp( $h, "\x89PNG\r\n\x1A\n", 8 ) ) {
			return 'png';
		}
		if ( 0 === strncmp( $h, 'GIF87a', 6 ) || 0 === strncmp( $h, 'GIF89a', 6 ) ) {
			return 'gif';
		}
		if ( 0 === strncmp( $h, 'RIFF', 4 ) && 'WEBP' === substr( $h, 8, 4 ) ) {
			return 'webp';
		}
		if ( 'ftyp' === substr( $h, 4, 4 ) ) {
			$brand = substr( $h, 8, 4 );
			if ( in_array( $brand, array( 'avif', 'avis' ), true ) ) {
				return 'avif';
			}
			if ( in_array( $brand, array( 'heic', 'heix', 'hevc', 'hevx', 'heim', 'heis', 'hevm', 'hevs', 'mif1', 'msf1' ), true ) ) {
				return 'heic';
			}
			return '';
		}
		if ( 0 === strncmp( $h, "\x00\x00\x01\x00", 4 ) || 0 === strncmp( $h, "\x00\x00\x02\x00", 4 ) ) {
			return 'ico';
		}
		if ( 0 === strncmp( $h, 'BM', 2 ) ) {
			return 'bmp';
		}
		if ( 0 === strncmp( $h, "II*\x00", 4 ) || 0 === strncmp( $h, "MM\x00*", 4 ) ) {
			return 'tiff';
		}
		return '';
	}

	/**
	 * Look for code anywhere a payload can hide in a media file: the whole file up to
	 * 2 MB, head 256 KB + tail 1 MB up to 64 MB, the last 1 MB beyond that.
	 *
	 * @return array hit ('php'|'phar'|''), offset, region (up to 512 KB from the hit, for indicators)
	 */
	public static function media_code_scan( $path, $size ) {
		$none = array( 'hit' => '', 'offset' => 0, 'region' => '' );
		$size = (int) $size;
		if ( $size <= 0 ) {
			return $none;
		}
		$chunks = array();
		if ( $size <= 2 * MB_IN_BYTES ) {
			$chunks[0] = (string) @file_get_contents( $path );
		} else {
			if ( $size <= 64 * MB_IN_BYTES ) {
				$chunks[0] = (string) @file_get_contents( $path, false, null, 0, 256 * KB_IN_BYTES );
			}
			$tail_at            = max( 0, $size - MB_IN_BYTES );
			$chunks[ $tail_at ] = (string) @file_get_contents( $path, false, null, $tail_at, MB_IN_BYTES );
		}
		$rules = array(
			// <?=: needs a variable, a call or a backtick after it - three random bytes
			// "<?=" in compressed image data must not raise an alarm.
			'php'  => '/<\?php[\s\/]|<\?=\s{0,3}(\$[A-Za-z_]|@?[A-Za-z_]\w*\s*\(|`)|eval\s*\(\s*(base64_decode|gzinflate)/i',
			'phar' => '/__HALT_COMPILER\s*\(\s*\)\s*;/i',
		);
		foreach ( $rules as $hit => $rx ) { // php outranks phar
			foreach ( $chunks as $base => $data ) {
				if ( '' !== $data && preg_match( $rx, $data, $m, PREG_OFFSET_CAPTURE ) ) {
					$offset = $base + (int) $m[0][1];
					return array(
						'hit'    => $hit,
						'offset' => $offset,
						'region' => (string) @file_get_contents( $path, false, null, $offset, 512 * KB_IN_BYTES ),
					);
				}
			}
		}
		return $none;
	}
}
