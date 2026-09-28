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
		$p = wp_parse_url( (string) $url );
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
		return isset( $_SERVER['REQUEST_URI'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), 0, 200 ) : '';
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
		// Sucuri, Wordfence, cache plugins: a data file whose first statement is exit.
		// Nothing after it can ever run - whatever the data contains, even "<?".
		return (bool) preg_match( '#^(\xEF\xBB\xBF)?\s*<\?php\s*(/\*.*?\*/\s*)?(exit|die)\s*(\(\s*(\d+|\'[^\'()$]*\'|"[^"()$]*")?\s*\))?\s*;#is', $head );
	}
}
