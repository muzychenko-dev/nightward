<?php
/**
 * Event registry. Every monitor and scanner reports here. Events are
 * deduplicated by fingerprint: the same thing seen 500 times is one row with
 * hits=500, and it can alert only once.
 */

namespace Nightward;

defined( 'ABSPATH' ) || exit;

class Events {

	const SEVERITIES = array( 'critical', 'high', 'medium', 'low', 'info' );

	private static $buffer = array();
	private static $hooked = false;
	private static $late   = false; // shutdown flush already ran: write immediately

	public static function rank( $sev ) {
		$i = array_search( $sev, self::SEVERITIES, true );
		return false === $i ? 9 : $i;
	}

	public static function severity_label( $sev ) {
		$l = array(
			'critical' => __( 'Critical', 'nightward' ),
			'high'     => __( 'High', 'nightward' ),
			'medium'   => __( 'Medium', 'nightward' ),
			'low'      => __( 'Low', 'nightward' ),
			'info'     => __( 'Info', 'nightward' ),
		);
		return isset( $l[ $sev ] ) ? $l[ $sev ] : $sev;
	}

	public static function module_label( $m ) {
		$l = array(
			'outbound'       => __( 'Outbound requests', 'nightward' ),
			'interception'   => __( 'HTTP interception', 'nightward' ),
			'hooks'          => __( 'Sensitive hooks', 'nightward' ),
			'privilege'      => __( 'Users & privileges', 'nightward' ),
			'options'        => __( 'Options', 'nightward' ),
			'cron'           => __( 'Scheduled tasks', 'nightward' ),
			'integrity'      => __( 'File integrity', 'nightward' ),
			'uploads'        => __( 'Executable files', 'nightward' ),
			'update_channel' => __( 'Update channel', 'nightward' ),
			'hardening'      => __( 'Hardening', 'nightward' ),
			'system'         => __( 'Nightward', 'nightward' ),
		);
		return isset( $l[ $m ] ) ? $l[ $m ] : $m;
	}

	/* ------------------------------------------------------------------ */
	/* Language-independent storage                                        */
	/*                                                                     */
	/* Events are recorded in whatever language the current request runs  */
	/* in (a visitor, WP-CLI, an admin with another locale). They are      */
	/* stored in English — translated strings are mapped back to their     */
	/* msgid — and translated again when shown or e-mailed.                */
	/* ------------------------------------------------------------------ */

	private static $rev = null;

	/** Translated string → original English msgid (identity when unknown). */
	public static function english( $s ) {
		if ( ! is_string( $s ) || '' === $s ) {
			return $s;
		}
		if ( null === self::$rev ) {
			self::$rev = array();
			$locale    = function_exists( 'determine_locale' ) ? determine_locale() : 'en_US';
			if ( 0 !== strpos( $locale, 'en' ) && function_exists( 'get_translations_for_domain' ) ) {
				$tr = get_translations_for_domain( 'nightward' );
				$entries = isset( $tr->entries ) ? $tr->entries : array();
				foreach ( (array) $entries as $entry ) {
					if ( ! empty( $entry->translations ) ) {
						foreach ( $entry->translations as $i => $t ) {
							if ( '' !== $t ) {
								self::$rev[ $t ] = 0 === $i || null === $entry->plural ? $entry->singular : $entry->plural;
							}
						}
					}
				}
			}
		}
		return isset( self::$rev[ $s ] ) ? self::$rev[ $s ] : $s;
	}

	/** Stored English string → current language. */
	public static function tr( $s ) {
		// phpcs:ignore WordPress.WP.I18n.NonSingularStringLiteralText
		return is_string( $s ) && '' !== $s && strlen( $s ) < 600 ? __( $s, 'nightward' ) : $s;
	}

	/** Stored string or array( format, ...args ) → current language. */
	public static function text( $v ) {
		if ( ! is_array( $v ) ) {
			return self::tr( $v );
		}
		$v   = array_values( $v );
		$fmt = self::tr( array_shift( $v ) );
		$out = @vsprintf( $fmt, array_map( array( __CLASS__, 'tr' ), $v ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return false === $out ? $fmt : $out;
	}

	/** Title of a stored event in the current language. */
	public static function title( $row ) {
		$d = self::details( $row );
		if ( ! empty( $d['_t'] ) && is_array( $d['_t'] ) ) {
			$t    = $d['_t'];
			$fmt  = self::tr( array_shift( $t ) );
			$args = array_map( array( __CLASS__, 'tr' ), $t );
			$out  = @vsprintf( $fmt, $args ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false === $out || '' === $out ? $row->title : $out;
		}
		return self::tr( $row->title );
	}

	/**
	 * @param array $e module, type, severity, title (string, or array( format, ...args ) for
	 *                 language-independent storage), details(array), component, file, line, key
	 */
	public static function record( array $e ) {
		$e = wp_parse_args( $e, array(
			'module' => 'system', 'type' => 'generic', 'severity' => 'info', 'title' => '',
			'details' => array(), 'component' => '', 'file' => '', 'line' => 0, 'key' => '',
		) );
		if ( is_array( $e['title'] ) ) {
			$t    = array_values( $e['title'] );
			$fmt  = self::english( array_shift( $t ) );
			$args = array_map( function ( $a ) {
				return is_scalar( $a ) ? self::english( (string) $a ) : '';
			}, $t );
			$e['details']['_t'] = array_merge( array( $fmt ), $args );
			$e['title']         = (string) @vsprintf( $fmt, $args ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		} else {
			$e['title'] = self::english( (string) $e['title'] );
		}
		foreach ( $e['details'] as $k => $v ) {
			if ( is_string( $v ) ) {
				$e['details'][ $k ] = self::english( $v );
			} elseif ( 'explanation' === $k && is_array( $v ) ) {
				$e['details'][ $k ] = array_map( function ( $a ) {
					return is_scalar( $a ) ? self::english( (string) $a ) : '';
				}, array_values( $v ) ); // array( format, ...args )
			}
		}
		if ( ! in_array( $e['severity'], self::SEVERITIES, true ) ) {
			$e['severity'] = 'info';
		}
		$key              = $e['key'] ? $e['key'] : implode( '|', array( $e['module'], $e['type'], $e['component'], $e['file'], $e['line'], $e['title'] ) );
		$e['fingerprint'] = sha1( $key );
		self::$buffer[ $e['fingerprint'] ] = $e;

		if ( ! self::$hooked ) {
			self::$hooked = true;
			add_action( 'shutdown', array( __CLASS__, 'flush' ), 1000 ); // після всіх моніторів, що пишуть на shutdown
		}
		// Critical events are written right away: the request might be killed
		// before shutdown (exit in a backdoor, fatal error).
		if ( ( 'critical' === $e['severity'] && did_action( 'plugins_loaded' ) ) || self::$late ) {
			self::flush();
		}
	}

	public static function flush() {
		if ( doing_action( 'shutdown' ) ) {
			self::$late = true;
		}
		if ( ! self::$buffer || ! DB::ready() ) {
			return;
		}
		global $wpdb;
		$t   = DB::events();
		$now = Util::now();
		$buf = self::$buffer;
		self::$buffer = array();

		foreach ( $buf as $fp => $e ) {
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT id, status, severity FROM {$t} WHERE fingerprint = %s", $fp ) ); // phpcs:ignore
			$details = wp_json_encode( $e['details'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR );
			$is_new  = false;
			if ( $row ) {
				$reopen = in_array( $row->status, array( 'resolved' ), true );
				$wpdb->query( $wpdb->prepare( // phpcs:ignore
					"UPDATE {$t} SET hits = hits + 1, last_seen = %s, details = %s, title = %s" . ( $reopen ? ", status = 'open', alerted = 0" : '' ) . ' WHERE id = %d',
					$now, $details, $e['title'], $row->id
				) );
				$is_new = $reopen;
				$id     = (int) $row->id;
			} else {
				$wpdb->insert( $t, array(
					'fingerprint' => $fp,
					'module'      => substr( $e['module'], 0, 32 ),
					'type'        => substr( $e['type'], 0, 64 ),
					'severity'    => $e['severity'],
					'title'       => mb_substr( $e['title'], 0, 250 ),
					'details'     => $details,
					'component'   => substr( (string) $e['component'], 0, 190 ),
					'file'        => substr( (string) $e['file'], 0, 250 ),
					'line'        => (int) $e['line'],
					'hits'        => 1,
					'status'      => 'open',
					'alerted'     => 0,
					'first_seen'  => $now,
					'last_seen'   => $now,
				) );
				$is_new = true;
				$id     = (int) $wpdb->insert_id;
			}
			if ( $is_new && $id ) {
				$e['id'] = $id;
				Reports::maybe_instant( $e );
				/**
				 * Fires when Nightward records a new (or re-opened) event.
				 *
				 * @param array $e Event data incl. id, severity, module, type, title, details.
				 */
				do_action( 'nightward_event', $e );
			}
		}
	}

	public static function query( array $args = array() ) {
		global $wpdb;
		$a = wp_parse_args( $args, array(
			'severity' => '', 'module' => '', 'status' => '', 'search' => '', 'since' => '',
			'limit' => 50, 'offset' => 0, 'min_severity' => '', 'order' => 'last_seen',
		) );
		$t     = DB::events();
		$where = array( '1=1' );
		$vals  = array();
		if ( $a['severity'] ) {
			$where[] = 'severity = %s';
			$vals[]  = $a['severity'];
		}
		if ( $a['min_severity'] ) {
			$allowed = array_slice( self::SEVERITIES, 0, self::rank( $a['min_severity'] ) + 1 );
			$where[] = 'severity IN (' . implode( ',', array_fill( 0, count( $allowed ), '%s' ) ) . ')';
			$vals    = array_merge( $vals, $allowed );
		}
		if ( $a['module'] ) {
			$where[] = 'module = %s';
			$vals[]  = $a['module'];
		}
		if ( $a['status'] ) {
			if ( is_array( $a['status'] ) ) {
				$where[] = 'status IN (' . implode( ',', array_fill( 0, count( $a['status'] ), '%s' ) ) . ')';
				$vals    = array_merge( $vals, $a['status'] );
			} else {
				$where[] = 'status = %s';
				$vals[]  = $a['status'];
			}
		}
		if ( $a['since'] ) {
			$where[] = 'last_seen >= %s';
			$vals[]  = $a['since'];
		}
		if ( $a['search'] ) {
			$like    = '%' . $wpdb->esc_like( $a['search'] ) . '%';
			$where[] = '(title LIKE %s OR component LIKE %s OR file LIKE %s OR details LIKE %s)';
			array_push( $vals, $like, $like, $like, $like );
		}
		$order = 'first_seen' === $a['order'] ? 'first_seen DESC' : 'last_seen DESC';
		$sql   = "SELECT * FROM {$t} WHERE " . implode( ' AND ', $where ) . " ORDER BY {$order} LIMIT %d OFFSET %d";
		$vals[] = (int) $a['limit'];
		$vals[] = (int) $a['offset'];
		$rows   = $wpdb->get_results( $wpdb->prepare( $sql, $vals ) ); // phpcs:ignore
		usort( $rows, function ( $x, $y ) use ( $a ) {
			if ( 'severity' === $a['order'] ) {
				return self::rank( $x->severity ) <=> self::rank( $y->severity ) ?: strcmp( $y->last_seen, $x->last_seen );
			}
			return 0;
		} );
		return $rows;
	}

	public static function count( array $args = array() ) {
		$args['limit']  = 100000;
		$args['offset'] = 0;
		return count( self::query( $args ) );
	}

	/** Open events per severity. */
	public static function open_counts() {
		global $wpdb;
		$t   = DB::events();
		$out = array_fill_keys( self::SEVERITIES, 0 );
		if ( ! DB::ready() ) {
			return $out;
		}
		foreach ( $wpdb->get_results( "SELECT severity, COUNT(*) AS n FROM {$t} WHERE status = 'open' GROUP BY severity" ) as $r ) { // phpcs:ignore
			$out[ $r->severity ] = (int) $r->n;
		}
		return $out;
	}

	public static function get( $id ) {
		global $wpdb;
		$t = DB::events();
		return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$t} WHERE id = %d", $id ) ); // phpcs:ignore
	}

	public static function set_status( array $ids, $status ) {
		global $wpdb;
		if ( ! in_array( $status, array( 'open', 'acknowledged', 'resolved', 'ignored' ), true ) || ! $ids ) {
			return 0;
		}
		$ids = array_map( 'intval', $ids );
		$t   = DB::events();
		return (int) $wpdb->query( $wpdb->prepare( // phpcs:ignore
			"UPDATE {$t} SET status = %s WHERE id IN (" . implode( ',', array_fill( 0, count( $ids ), '%d' ) ) . ')',
			array_merge( array( $status ), $ids )
		) );
	}

	/** Mark matching events resolved (e.g. a file that was restored). */
	public static function resolve_by( $module, $type, $file ) {
		global $wpdb;
		$t = DB::events();
		$wpdb->query( $wpdb->prepare( "UPDATE {$t} SET status = 'resolved' WHERE module = %s AND type = %s AND file = %s AND status IN ('open','acknowledged')", $module, $type, $file ) ); // phpcs:ignore
	}

	public static function mark_alerted( array $ids ) {
		global $wpdb;
		if ( ! $ids ) {
			return;
		}
		$t = DB::events();
		$wpdb->query( "UPDATE {$t} SET alerted = 1 WHERE id IN (" . implode( ',', array_map( 'intval', $ids ) ) . ')' ); // phpcs:ignore
	}

	public static function purge( $days ) {
		global $wpdb;
		$t = DB::events();
		$cut = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS * (int) $days );
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$t} WHERE last_seen < %s AND status IN ('resolved','ignored','acknowledged')", $cut ) ); // phpcs:ignore
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$t} WHERE last_seen < %s AND severity IN ('info','low')", $cut ) ); // phpcs:ignore
		$e = DB::egress();
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$e} WHERE last_seen < %s", gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS * 180 ) ) ); // phpcs:ignore
	}

	public static function details( $row ) {
		$d = json_decode( (string) $row->details, true );
		return is_array( $d ) ? $d : array();
	}
}
