<?php
/**
 * Outbound HTTP monitor + interception detector.
 *
 * Every wp_remote_* call is attributed to the plugin/theme file and line that
 * made it. A sentinel is interleaved after EVERY callback on pre_http_request,
 * so when a response is faked we know exactly which callback did it — even
 * with five anonymous closures on priority 10.
 *
 * Blind spot (documented in the UI): raw curl_exec(), fsockopen() and
 * file_get_contents('https://…') bypass the WordPress HTTP API.
 */

namespace Nightward\Monitor;

use Nightward\Attribution;
use Nightward\DB;
use Nightward\Events;
use Nightward\Settings;
use Nightward\Util;

defined( 'ABSPATH' ) || exit;

class Outbound {

	const PROBE_HEADER = 'X-Nightward-Probe';

	private static $requests     = array();   // this PHP request's outbound calls
	private static $stack        = array();   // nested pre_http_request chains
	private static $sentinel_cbs = array();   // sentinel id => original callback
	private static $instrumented = '';
	private static $seq          = 0;

	public static function init() {
		add_filter( 'pre_http_request', array( __CLASS__, 'first' ), -99999, 3 );
		add_filter( 'pre_http_request', array( __CLASS__, 'last' ), PHP_INT_MAX, 3 );
		add_action( 'http_api_debug', array( __CLASS__, 'result' ), PHP_INT_MAX, 5 );
		add_action( 'shutdown', array( __CLASS__, 'flush' ), 15 );
	}

	private static function is_probe( $args ) {
		return ! empty( $args['headers'] ) && is_array( $args['headers'] ) && isset( $args['headers'][ self::PROBE_HEADER ] );
	}

	public static function first( $pre, $args, $url ) {
		$host = Util::host_of( $url );
		$id   = ++self::$seq;
		$c    = Attribution::caller();
		self::$requests[ $id ] = array(
			'host'      => $host,
			'url'       => Util::redact_url( $url ),
			'method'    => isset( $args['method'] ) ? strtoupper( (string) $args['method'] ) : 'GET',
			'component' => $c['component'],
			'file'      => $c['file'],
			'line'      => $c['line'],
			'probe'     => self::is_probe( $args ),
			'intercept' => null,
			'code'      => null,
			'error'     => null,
			'sslverify' => ! ( isset( $args['sslverify'] ) && ! $args['sslverify'] ),
		);
		self::$stack[] = array( 'id' => $id, 'pre' => $pre, 'url' => $url );

		if ( ! self::$requests[ $id ]['probe'] ) {
			self::check_destination( self::$requests[ $id ], $url );
		}
		if ( false !== $pre ) {
			// Хтось на пріоритеті нижчому за -99999 — рідкість, але фіксуємо.
			self::intercepted( $id, $pre, null, $url );
		}
		self::instrument();
		return $pre;
	}

	/** Sentinel after every foreign callback. Rebuilt only when the callback set changes. */
	private static function instrument() {
		global $wp_filter;
		if ( empty( $wp_filter['pre_http_request'] ) || ! ( $wp_filter['pre_http_request'] instanceof \WP_Hook ) ) {
			return;
		}
		$hook = $wp_filter['pre_http_request'];
		$sig  = array();
		foreach ( $hook->callbacks as $prio => $cbs ) {
			foreach ( $cbs as $cid => $cb ) {
				if ( 0 !== strpos( (string) $cid, 'nightward_s_' ) ) {
					$sig[] = $prio . ':' . $cid;
				}
			}
		}
		$sig = md5( implode( ',', $sig ) );
		if ( $sig === self::$instrumented ) {
			return;
		}
		self::$instrumented = $sig;
		self::$sentinel_cbs = array();
		$n = 0;
		foreach ( $hook->callbacks as $prio => $cbs ) {
			$rebuilt = array();
			foreach ( $cbs as $cid => $cb ) {
				if ( 0 === strpos( (string) $cid, 'nightward_s_' ) ) {
					continue;
				}
				$rebuilt[ $cid ] = $cb;
				if ( self::is_own( $cb['function'] ) ) {
					continue;
				}
				$sid                        = 'nightward_s_' . ( ++$n );
				self::$sentinel_cbs[ $sid ] = $cb['function'];
				$rebuilt[ $sid ]            = array(
					'function'      => self::sentinel( $sid ),
					'accepted_args' => 3,
				);
			}
			$hook->callbacks[ $prio ] = $rebuilt;
		}
	}

	private static function is_own( $fn ) {
		return is_array( $fn ) && isset( $fn[0] ) && ( __CLASS__ === $fn[0] || ( is_string( $fn[0] ) && 0 === strpos( $fn[0], 'Nightward\\' ) ) );
	}

	private static function sentinel( $sid ) {
		return function ( $pre, $args = array(), $url = '' ) use ( $sid ) {
			$top = count( self::$stack ) - 1;
			if ( $top < 0 ) {
				return $pre;
			}
			$prev = self::$stack[ $top ]['pre'];
			if ( $pre !== $prev ) {
				self::$stack[ $top ]['pre'] = $pre;
				if ( false !== $pre ) {
					$cb = isset( self::$sentinel_cbs[ $sid ] ) ? self::$sentinel_cbs[ $sid ] : null;
					self::intercepted( self::$stack[ $top ]['id'], $pre, $cb, self::$stack[ $top ]['url'], false !== $prev );
				}
			}
			return $pre;
		};
	}

	public static function last( $pre, $args, $url ) {
		$frame = array_pop( self::$stack );
		if ( $frame && false !== $pre && empty( self::$requests[ $frame['id'] ]['intercept'] ) ) {
			// Зареєстровано вже після інструментування — винуватця точно не знаємо.
			self::intercepted( $frame['id'], $pre, null, $url );
		}
		return $pre;
	}

	public static function result( $response, $context, $class, $args, $url ) {
		if ( 'response' !== $context ) {
			return;
		}
		for ( $i = self::$seq; $i > 0; $i-- ) {
			if ( isset( self::$requests[ $i ] ) && null === self::$requests[ $i ]['code'] && null === self::$requests[ $i ]['error']
				&& self::$requests[ $i ]['host'] === Util::host_of( $url ) ) {
				if ( is_wp_error( $response ) ) {
					self::$requests[ $i ]['error'] = $response->get_error_code();
				} else {
					self::$requests[ $i ]['code'] = (int) wp_remote_retrieve_response_code( $response );
				}
				break;
			}
		}
	}

	private static function check_destination( array $r, $url ) {
		$host = $r['host'];
		if ( ! $host || Util::is_own_host( $host ) ) {
			return;
		}
		$trusted = Settings::trusted_hosts();
		if ( in_array( $host, $trusted, true ) || in_array( Util::registrable( $host ), $trusted, true ) ) {
			return; // адміністратор явно довірив цей хост (напр. власний Telegram-бот)
		}
		$why  = Util::bad_host_reason( $host );
		$sev  = 'critical';
		if ( ! $why && Util::is_public_ip_literal( $host ) ) {
			$why = __( 'raw IP address instead of a domain', 'nightward' );
			$sev = 'high';
		}
		if ( ! $why ) {
			$why = Util::bad_url_reason( $url );
			$sev = 'medium';
		}
		if ( ! $why ) {
			return;
		}
		Events::record( array(
			'module'    => 'outbound',
			'type'      => 'suspicious_destination',
			'severity'  => $sev,
			/* translators: 1: host, 2: reason, 3: plugin/theme name */
			'title'     => array( __( 'Request to %1$s (%2$s) from %3$s', 'nightward' ), $host, $why, Attribution::label( $r['component'] ) ),
			'details'   => array( 'url' => $r['url'], 'method' => $r['method'], 'reason' => $why, 'context' => Util::request_context() ),
			'component' => $r['component'],
			'file'      => $r['file'],
			'line'      => $r['line'],
			'key'       => 'outbound|dest|' . $host . '|' . $r['component'],
		) );
	}

	private static function intercepted( $id, $pre, $cb, $url, $overwrote = false ) {
		if ( empty( self::$requests[ $id ] ) ) {
			return;
		}
		$r    = &self::$requests[ $id ];
		$info = $cb ? Attribution::callback_info( $cb ) : array( 'name' => __( 'unknown callback', 'nightward' ), 'file' => '', 'line' => 0, 'component' => 'unknown', 'kind' => '' );
		$code = null;
		$body = '';
		$shape = is_wp_error( $pre ) ? 'WP_Error' : gettype( $pre );
		if ( is_array( $pre ) ) {
			$code = isset( $pre['response']['code'] ) ? (int) $pre['response']['code'] : null;
			$body = isset( $pre['body'] ) && is_string( $pre['body'] ) ? $pre['body'] : '';
		}
		$r['intercept'] = array( 'by' => $info['component'], 'file' => $info['file'], 'line' => $info['line'], 'code' => $code, 'shape' => $shape );
		if ( $r['probe'] || 'nightward' === $info['component'] ) {
			return;
		}

		// Скільки різних доменів цей callback уже підміняв — «глушить усе» чи вузький.
		$culprit = $info['file'] . ':' . $info['line'];
		$seen    = (array) get_option( 'nightward_intercept_hosts', array() );
		$reg     = Util::registrable( $r['host'] );
		if ( ! isset( $seen[ $culprit ] ) ) {
			$seen[ $culprit ] = array();
		}
		if ( ! in_array( $reg, $seen[ $culprit ], true ) && count( $seen[ $culprit ] ) < 20 ) {
			$seen[ $culprit ][] = $reg;
			update_option( 'nightward_intercept_hosts', array_slice( $seen, -200, null, true ), false );
		}
		$n_hosts = count( $seen[ $culprit ] );

		$path = (string) wp_parse_url( $url, PHP_URL_PATH ) . ' ' . (string) wp_parse_url( $url, PHP_URL_QUERY );
		$sev  = 'medium';
		$why  = __( 'Response replaced before the request reached the network.', 'nightward' );
		if ( 'WP_Error' === $shape ) {
			$sev = 'low';
			$why = __( 'Request blocked (WP_Error returned). Typical for "disable external requests" tools.', 'nightward' );
		} elseif ( in_array( $reg, array( 'wordpress.org', 'w.org' ), true ) ) {
			$sev = 'high';
			$why = __( 'WordPress.org API response is faked: update and security information for this site may be false.', 'nightward' );
		} elseif ( preg_match( '/licen|activat|verif|validat|check|register|update|version|entitle|purchase/i', $path ) && 200 === $code ) {
			$sev = 'high';
			$why = __( 'A licence / update verification response is fabricated. This is how pirated ("nulled") plugins bypass licensing.', 'nightward' );
		}
		if ( $n_hosts >= 3 ) {
			$sev = 'critical';
			/* translators: %d: number of domains */
			$why = array( __( 'The same callback has faked responses for %d different domains: it can intercept any outbound request of this site.', 'nightward' ), $n_hosts );
		}
		if ( 'eval' === $info['component'] ) {
			$sev = 'critical';
			$why = __( 'The intercepting callback was created with eval().', 'nightward' );
		}

		Events::record( array(
			'module'    => 'interception',
			'type'      => 'http_faked',
			'severity'  => $sev,
			/* translators: 1: host, 2: plugin/theme name */
			'title'     => array( __( 'Responses for %1$s are faked by %2$s', 'nightward' ), $r['host'], Attribution::label( $info['component'] ) ),
			'details'   => array(
				'explanation'  => $why,
				'url'          => $r['url'],
				'callback'     => $info['name'],
				'fake_code'    => $code,
				'fake_body'    => mb_substr( preg_replace( '/\s+/', ' ', $body ), 0, 200 ),
				'response'     => $shape,
				'requested_by' => Attribution::label( $r['component'] ) . ( $r['file'] ? ' — ' . $r['file'] . ':' . $r['line'] : '' ),
				'hosts_faked'  => $seen[ $culprit ],
				'overwrote'    => $overwrote,
			),
			'component' => $info['component'],
			'file'      => $info['file'],
			'line'      => $info['line'],
			'key'       => 'interception|' . $culprit . '|' . $reg . '|' . ( $n_hosts >= 3 ? 'wide' : 'narrow' ),
		) );
	}

	/** One upsert per host+component at the end of the request. */
	public static function flush() {
		if ( ! self::$requests || ! DB::ready() ) {
			return;
		}
		global $wpdb;
		$t        = DB::egress();
		$now      = Util::now();
		$learning = Settings::in_learning();
		$trusted  = Settings::trusted_hosts();
		$agg      = array();
		foreach ( self::$requests as $r ) {
			if ( $r['probe'] || ! $r['host'] ) {
				continue;
			}
			$k = $r['host'] . '|' . $r['component'];
			if ( ! isset( $agg[ $k ] ) ) {
				$agg[ $k ] = array( 'r' => $r, 'hits' => 0, 'int' => 0, 'err' => 0 );
			}
			$agg[ $k ]['hits']++;
			$agg[ $k ]['int'] += $r['intercept'] ? 1 : 0;
			$agg[ $k ]['err'] += $r['error'] ? 1 : 0;
		}
		foreach ( $agg as $a ) {
			$r  = $a['r'];
			$id = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$t} WHERE host = %s AND component = %s", $r['host'], $r['component'] ) ); // phpcs:ignore
			if ( $id ) {
				$wpdb->query( $wpdb->prepare( "UPDATE {$t} SET hits = hits + %d, intercepted = intercepted + %d, errors = errors + %d, last_seen = %s, sample_url = %s WHERE id = %d", $a['hits'], $a['int'], $a['err'], $now, $r['url'], $id ) ); // phpcs:ignore
				continue;
			}
			$wpdb->insert( $t, array(
				'host' => $r['host'], 'component' => substr( $r['component'], 0, 190 ), 'sample_url' => $r['url'],
				'hits' => $a['hits'], 'intercepted' => $a['int'], 'errors' => $a['err'], 'first_seen' => $now, 'last_seen' => $now,
			) );
			if ( $learning || $a['int'] === $a['hits'] ) {
				continue; // під час навчання і для повністю перехоплених (їх вже описано подією) — тихо
			}
			self::new_host_event( $r, $trusted );
		}
		self::$requests = array();
	}

	private static function new_host_event( array $r, array $trusted ) {
		$host = $r['host'];
		$reg  = Util::registrable( $host );
		if ( Util::is_own_host( $host ) || in_array( $host, $trusted, true ) || in_array( $reg, $trusted, true ) ) {
			return;
		}
		if ( Util::bad_host_reason( $host ) || Util::is_public_ip_literal( $host ) ) {
			return; // вже є окрема подія з вищою серйозністю
		}
		$vendor = Attribution::vendor_domains( $r['component'] );
		if ( in_array( $reg, $vendor, true ) || 'core' === $r['component'] ) {
			return; // власний домен плагіна або ядро WP
		}
		$infra = in_array( $reg, Util::infra_hosts(), true );
		Events::record( array(
			'module'    => 'outbound',
			'type'      => 'new_host',
			'severity'  => $infra ? 'info' : 'low',
			/* translators: 1: plugin/theme name, 2: host */
			'title'     => array( __( '%1$s contacted a new host: %2$s', 'nightward' ), Attribution::label( $r['component'] ), $host ),
			'details'   => array(
				'url'        => $r['url'],
				'method'     => $r['method'],
				'context'    => Util::request_context(),
				'vendor'     => $vendor,
				'sslverify'  => $r['sslverify'],
				'note'       => $infra ? __( 'Well-known service.', 'nightward' ) : __( 'Not the plugin\'s own domain. Check what data is sent there.', 'nightward' ),
			),
			'component' => $r['component'],
			'file'      => $r['file'],
			'line'      => $r['line'],
			'key'       => 'outbound|new|' . $host . '|' . $r['component'],
		) );
	}

	/** For the admin table. */
	public static function rows( $days = 30, $limit = 300 ) {
		global $wpdb;
		$t = DB::egress();
		return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$t} WHERE last_seen >= %s ORDER BY last_seen DESC LIMIT %d", gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS * $days ), $limit ) ); // phpcs:ignore
	}

	public static function new_since( $since ) {
		global $wpdb;
		$t = DB::egress();
		return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$t} WHERE first_seen >= %s ORDER BY first_seen DESC LIMIT 50", $since ) ); // phpcs:ignore
	}

	public static function stats_since( $since ) {
		global $wpdb;
		$t = DB::egress();
		$r = $wpdb->get_row( $wpdb->prepare( "SELECT COUNT(DISTINCT host) AS hosts, SUM(intercepted) AS intercepted FROM {$t} WHERE last_seen >= %s", $since ) ); // phpcs:ignore
		return array( 'hosts' => $r ? (int) $r->hosts : 0, 'intercepted' => $r ? (int) $r->intercepted : 0 );
	}
}
