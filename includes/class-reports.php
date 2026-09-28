<?php
/**
 * E-mail: the daily digest at the configured local time and instant alerts
 * for critical events. HTML with inline styles only — mail clients strip
 * <style> blocks and external CSS.
 */

namespace Nightward;

defined( 'ABSPATH' ) || exit;

class Reports {

	const QUEUE = 'nightward_instant_queue';
	const SENT  = 'nightward_instant_sent';

	private static $mail_error = '';

	/* ------------------------------------------------------------------ */
	/* Instant alerts                                                      */
	/* ------------------------------------------------------------------ */

	public static function maybe_instant( array $e ) {
		if ( ! Settings::get( 'instant_enabled', 1 ) ) {
			return;
		}
		$min = Settings::get( 'instant_min_severity', 'critical' );
		if ( Events::rank( $e['severity'] ) > Events::rank( $min ) ) {
			return;
		}
		$sent = array_filter( (array) get_option( self::SENT, array() ), function ( $t ) {
			return $t > time() - HOUR_IN_SECONDS;
		} );
		$max = (int) Settings::get( 'instant_max_per_hour', 5 );
		if ( count( $sent ) >= $max || ! function_exists( 'wp_mail' ) || ! did_action( 'plugins_loaded' ) ) {
			// Ліміт — складаємо в чергу, підуть одним листом.
			$q   = (array) get_option( self::QUEUE, array() );
			$q[] = (int) $e['id'];
			update_option( self::QUEUE, array_slice( array_unique( $q ), -100 ), false );
			if ( ! wp_next_scheduled( 'nightward_instant_retry' ) ) {
				$oldest = $sent ? min( $sent ) : time();
				wp_schedule_single_event( max( time() + 60, $oldest + HOUR_IN_SECONDS + 30 ), 'nightward_instant_retry' );
			}
			return;
		}
		$row = Events::get( $e['id'] );
		if ( ! $row ) {
			return;
		}
		if ( self::send_alert( array( $row ) ) ) {
			$sent[] = time();
			update_option( self::SENT, array_values( $sent ), false );
			Events::mark_alerted( array( (int) $row->id ) );
		}
	}

	public static function send_pending_instant() {
		$q = (array) get_option( self::QUEUE, array() );
		delete_option( self::QUEUE );
		$rows = array();
		foreach ( $q as $id ) {
			$r = Events::get( $id );
			if ( $r && ! $r->alerted && in_array( $r->status, array( 'open' ), true ) ) {
				$rows[] = $r;
			}
		}
		if ( $rows && self::send_alert( $rows ) ) {
			Events::mark_alerted( wp_list_pluck( $rows, 'id' ) );
			$sent   = (array) get_option( self::SENT, array() );
			$sent[] = time();
			update_option( self::SENT, array_slice( $sent, -50 ), false );
		}
	}

	private static function send_alert( array $rows ) {
		$first = $rows[0];
		$site  = self::site_name();
		$subj  = self::with_locale( function () use ( $rows, $first, $site ) {
			$sev = mb_strtoupper( Events::severity_label( $first->severity ) );
			return 1 === count( $rows )
				/* translators: 1: severity, 2: site, 3: title */
				? sprintf( __( '[Nightward] %1$s on %2$s: %3$s', 'nightward' ), $sev, $site, Events::title( $first ) )
				/* translators: 1: count, 2: site */
				: sprintf( _n( '[Nightward] %1$d security alert on %2$s', '[Nightward] %1$d security alerts on %2$s', count( $rows ), 'nightward' ), count( $rows ), $site );
		} );
		return self::mail( $subj, self::with_locale( function () use ( $rows ) {
			return self::render_alert( $rows );
		} ) );
	}

	/* ------------------------------------------------------------------ */
	/* Daily digest                                                        */
	/* ------------------------------------------------------------------ */

	public static function send_digest( $to = '', $test = false ) {
		$last  = (int) get_option( 'nightward_last_report_sent', 0 );
		$since = $last && ! $test ? $last : time() - DAY_IN_SECONDS;
		$data  = self::collect( $since );
		if ( ! $test && ! $data['new_total'] && ! Settings::get( 'report_send_empty', 1 ) ) {
			return false;
		}
		$subject = self::with_locale( function () use ( $data, $test ) {
			return self::digest_subject( $data, $test );
		} );
		$html = self::with_locale( function () use ( $data, $test ) {
			return self::render_digest( $data, $test );
		} );
		$ok = self::mail( $subject, $html, $to );
		if ( $ok && ! $test ) {
			update_option( 'nightward_last_report_sent', time(), false );
		}
		return $ok;
	}

	public static function collect( $since_ts ) {
		$since = gmdate( 'Y-m-d H:i:s', $since_ts );
		$new   = Events::query( array( 'since' => $since, 'order' => 'first_seen', 'limit' => 500, 'status' => array( 'open', 'acknowledged' ) ) );
		// Тільки ті, що з'явились (або повернулись) у цьому періоді.
		$new = array_values( array_filter( $new, function ( $r ) use ( $since ) {
			return $r->first_seen >= $since || $r->last_seen >= $since && 'open' === $r->status && $r->hits > 1 && Events::rank( $r->severity ) <= 1;
		} ) );
		$by = array_fill_keys( Events::SEVERITIES, 0 );
		foreach ( $new as $r ) {
			$by[ $r->severity ]++;
		}
		usort( $new, function ( $a, $b ) {
			return Events::rank( $a->severity ) <=> Events::rank( $b->severity ) ?: strcmp( $b->last_seen, $a->last_seen );
		} );
		return array(
			'since'       => $since_ts,
			'events'      => $new,
			'by'          => $by,
			'new_total'   => count( array_filter( $new, function ( $r ) {
				return 'info' !== $r->severity;
			} ) ),
			'open'        => Events::open_counts(),
			'hosts'       => Monitor\Outbound::new_since( $since ),
			'net'         => Monitor\Outbound::stats_since( $since ),
			'integrity'   => get_option( Scanner\Integrity::LAST ),
			'hardening'   => Scanner\Hardening::score(),
			'cron'        => Cron::health(),
			'uploads'     => get_option( 'nightward_uploads_last' ),
		);
	}

	private static function digest_subject( array $d, $test ) {
		$site  = self::site_name();
		$parts = array();
		$n = $d['by'];
		if ( $n['critical'] ) {
			/* translators: %d: number of critical findings */
			$parts[] = sprintf( _n( '%d critical', '%d critical', $n['critical'], 'nightward' ), $n['critical'] );
		}
		if ( $n['high'] ) {
			/* translators: %d: number of high-severity findings */
			$parts[] = sprintf( _n( '%d high', '%d high', $n['high'], 'nightward' ), $n['high'] );
		}
		if ( $n['medium'] ) {
			/* translators: %d: number of medium-severity findings */
			$parts[] = sprintf( _n( '%d medium', '%d medium', $n['medium'], 'nightward' ), $n['medium'] );
		}
		$prefix = $test ? __( '[Nightward test]', 'nightward' ) : '[Nightward]';
		if ( ! $parts ) {
			/* translators: 1: prefix, 2: site, 3: date */
			return sprintf( __( '%1$s %2$s: all clear — %3$s', 'nightward' ), $prefix, $site, wp_date( 'j M' ) );
		}
		/* translators: 1: prefix, 2: site, 3: counts, 4: date */
		return sprintf( __( '%1$s %2$s: %3$s — %4$s', 'nightward' ), $prefix, $site, implode( ', ', $parts ), wp_date( 'j M' ) );
	}

	/* ------------------------------------------------------------------ */
	/* Rendering                                                           */
	/* ------------------------------------------------------------------ */

	public static function colors( $sev ) {
		$c = array(
			'critical' => array( '#b42318', '#fef3f2', '#fecdca' ),
			'high'     => array( '#b54708', '#fffaeb', '#fedf89' ),
			'medium'   => array( '#175cd3', '#eff8ff', '#b2ddff' ),
			'low'      => array( '#475467', '#f9fafb', '#eaecf0' ),
			'info'     => array( '#475467', '#f9fafb', '#eaecf0' ),
			'ok'       => array( '#067647', '#ecfdf3', '#abefc6' ),
		);
		return isset( $c[ $sev ] ) ? $c[ $sev ] : $c['info'];
	}

	private static function esc( $s ) {
		return esc_html( (string) $s );
	}

	private static function wrap( $inner, $preheader = '' ) {
		$font = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
		$html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"></head>'
			. '<body style="margin:0;padding:0;background:#f2f4f7;font-family:' . $font . ';color:#101828;">'
			. '<div style="display:none;max-height:0;overflow:hidden;opacity:0;">' . self::esc( $preheader ) . '</div>'
			. '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f2f4f7;"><tr><td align="center" style="padding:24px 12px;">'
			. '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;background:#ffffff;border:1px solid #eaecf0;border-radius:12px;">'
			. '<tr><td style="padding:20px 28px;border-bottom:1px solid #eaecf0;">'
			. '<table role="presentation" width="100%"><tr><td style="font-size:15px;font-weight:700;letter-spacing:.2px;color:#101828;">'
			. '<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#1d2939;margin-right:8px;vertical-align:middle;"></span>Nightward</td>'
			. '<td align="right" style="font-size:13px;color:#667085;">' . self::esc( self::site_name() ) . '</td></tr></table></td></tr>'
			. $inner
			. '<tr><td style="padding:18px 28px;border-top:1px solid #eaecf0;font-size:12px;line-height:1.6;color:#667085;">'
			/* translators: %s: site URL */
			. sprintf( self::esc( __( 'Sent by Nightward from %s. Report time, recipients and alert level can be changed in Nightward → Settings.', 'nightward' ) ), '<a href="' . esc_url( home_url( '/' ) ) . '" style="color:#475467;">' . self::esc( wp_parse_url( home_url(), PHP_URL_HOST ) ) . '</a>' )
			. '</td></tr></table></td></tr></table></body></html>';
		// Line breaks between blocks: tools that strip tags (Telegram/Slack bridges, plain-text
		// clients) otherwise glue words together. Browsers ignore this whitespace.
		return preg_replace( array( '#(</(div|tr|table|p)>)#', '#(</(td|span)>)#' ), array( "$1\n", '$1 ' ), $html );
	}

	private static function button( $url, $label ) {
		return '<a href="' . esc_url( $url ) . '" style="display:inline-block;background:#1d2939;color:#ffffff;text-decoration:none;font-size:14px;font-weight:600;padding:10px 18px;border-radius:8px;">' . self::esc( $label ) . '</a>';
	}

	private static function pill( $sev ) {
		list( $fg, $bg, $bd ) = self::colors( $sev );
		return '<span style="display:inline-block;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;color:' . $fg . ';background:' . $bg . ';border:1px solid ' . $bd . ';border-radius:999px;padding:2px 8px;">' . self::esc( Events::severity_label( $sev ) ) . '</span>';
	}

	public static function detail_label( $k ) {
		$l = array(
			'url' => __( 'URL', 'nightward' ), 'method' => __( 'Method', 'nightward' ), 'reason' => __( 'Reason', 'nightward' ),
			'context' => __( 'Request type', 'nightward' ), 'callback' => __( 'Callback', 'nightward' ), 'fake_code' => __( 'Fake HTTP status', 'nightward' ),
			'fake_body' => __( 'Fake response', 'nightward' ), 'response' => __( 'Returned', 'nightward' ), 'requested_by' => __( 'Requested by', 'nightward' ),
			'hosts_faked' => __( 'Domains faked', 'nightward' ), 'hook' => __( 'Hook', 'nightward' ), 'area' => __( 'Area', 'nightward' ),
			'priority' => __( 'Priority', 'nightward' ), 'user' => __( 'User', 'nightward' ), 'email' => __( 'E-mail', 'nightward' ),
			'done_by' => __( 'Done by', 'nightward' ), 'request' => __( 'Request', 'nightward' ), 'ip' => __( 'IP address', 'nightward' ),
			'old' => __( 'Old value', 'nightward' ), 'new' => __( 'New value', 'nightward' ), 'package' => __( 'Package', 'nightward' ),
			'size' => __( 'Size', 'nightward' ), 'modified' => __( 'Modified', 'nightward' ), 'indicators' => __( 'Malware indicators', 'nightward' ),
			'preview' => __( 'Beginning of file', 'nightward' ), 'fix' => __( 'How to fix', 'nightward' ), 'advice' => __( 'What to do', 'nightward' ),
			'injectors' => __( 'Code that can alter updates', 'nightward' ), 'recurrence' => __( 'Recurrence', 'nightward' ), 'next_run' => __( 'Next run', 'nightward' ),
			'handler' => __( 'Handler', 'nightward' ), 'args' => __( 'Arguments', 'nightward' ), 'vendor' => __( 'Vendor domains', 'nightward' ),
			'note' => __( 'Note', 'nightward' ), 'largest' => __( 'Largest', 'nightward' ), 'files' => __( 'Files', 'nightward' ),
			'old_email' => __( 'Old e-mail', 'nightward' ), 'new_email' => __( 'New e-mail', 'nightward' ), 'network' => __( 'Network', 'nightward' ),
			'user_agent' => __( 'Browser', 'nightward' ), 'blocked' => __( 'Blocked', 'nightward' ), 'hint' => __( 'Hint', 'nightward' ),
			'registered' => __( 'Registered', 'nightward' ), 'owner' => __( 'File owner', 'nightward' ), 'created_by' => __( 'Created by', 'nightward' ),
			'changed_by' => __( 'Changed by', 'nightward' ), 'eval_origin' => __( 'eval() called in', 'nightward' ), 'method_used' => __( 'Method', 'nightward' ),
			'samples' => __( 'Sampled page views', 'nightward' ), 'instances' => __( 'Instances', 'nightward' ), 'sslverify' => __( 'TLS verification', 'nightward' ),
		);
		return isset( $l[ $k ] ) ? $l[ $k ] : ucfirst( str_replace( '_', ' ', $k ) );
	}

	/** Plain details → "label: value" pairs, skipping noise. */
	public static function detail_pairs( array $d ) {
		$out  = array();
		$skip = array( 'explanation', 'user_id', 'overwrote', 'known', 'wporg_listing', '_t' );
		foreach ( $d as $k => $v ) {
			if ( in_array( $k, $skip, true ) || '' === $v || null === $v || array() === $v ) {
				continue;
			}
			if ( is_bool( $v ) ) {
				$v = $v ? __( 'yes', 'nightward' ) : __( 'no', 'nightward' );
			} elseif ( is_array( $v ) ) {
				$v = implode( ', ', array_map( function ( $x ) {
					return is_scalar( $x ) ? (string) $x : wp_json_encode( $x );
				}, $v ) );
			}
			$out[ self::detail_label( $k ) ] = (string) Events::tr( $v );
		}
		return $out;
	}

	private static function where( $r ) {
		$bits = array();
		if ( $r->component ) {
			$bits[] = Attribution::label( $r->component );
		}
		if ( $r->file ) {
			$bits[] = $r->file . ( $r->line ? ':' . $r->line : '' );
		}
		return implode( ' — ', $bits );
	}

	public static function render_alert( array $rows ) {
		$worst = $rows[0]->severity;
		list( $fg, $bg, $bd ) = self::colors( $worst );
		$inner = '<tr><td style="padding:22px 28px 6px;"><div style="background:' . $bg . ';border:1px solid ' . $bd . ';border-radius:10px;padding:14px 16px;">'
			. '<div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:' . $fg . ';">'
			. self::esc( 1 === count( $rows ) ? __( 'Security alert', 'nightward' ) : sprintf( /* translators: %d: count */ _n( '%d security alert', '%d security alerts', count( $rows ), 'nightward' ), count( $rows ) ) ) . '</div>'
			. '<div style="font-size:13px;color:#344054;margin-top:4px;">' . self::esc( __( 'Detected just now. This message is sent at the moment of detection, not in the daily report.', 'nightward' ) ) . '</div>'
			. '</div></td></tr>';
		foreach ( array_slice( $rows, 0, 10 ) as $r ) {
			$d      = Events::details( $r );
			$inner .= '<tr><td style="padding:14px 28px 4px;">' . self::pill( $r->severity )
				. ' <span style="font-size:12px;color:#667085;margin-left:6px;">' . self::esc( Events::module_label( $r->module ) ) . ' · ' . self::esc( Util::local_time( $r->first_seen ) ) . '</span>'
				. '<div style="font-size:17px;font-weight:700;line-height:1.35;margin:8px 0 6px;color:#101828;">' . self::esc( Events::title( $r ) ) . '</div>';
			if ( ! empty( $d['explanation'] ) ) {
				$inner .= '<div style="font-size:14px;line-height:1.55;color:#344054;margin-bottom:10px;">' . self::esc( Events::text( $d['explanation'] ) ) . '</div>';
			}
			$where = self::where( $r );
			$pairs = self::detail_pairs( $d );
			if ( $where ) {
				$pairs = array( __( 'Source', 'nightward' ) => $where ) + $pairs;
			}
			$inner .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;border:1px solid #eaecf0;border-radius:8px;">';
			foreach ( $pairs as $k => $v ) {
				$inner .= '<tr><td style="padding:7px 10px;color:#667085;width:34%;vertical-align:top;border-bottom:1px solid #f2f4f7;">' . self::esc( $k ) . '</td>'
					. '<td style="padding:7px 10px;color:#101828;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;word-break:break-all;border-bottom:1px solid #f2f4f7;">' . self::esc( mb_substr( $v, 0, 400 ) ) . '</td></tr>';
			}
			$inner .= '</table></td></tr>';
		}
		$inner .= '<tr><td style="padding:18px 28px 24px;">' . self::button( admin_url( 'admin.php?page=nightward&tab=events&event=' . (int) $rows[0]->id ), __( 'Open in Nightward', 'nightward' ) ) . '</td></tr>';
		return self::wrap( $inner, Events::title( $rows[0] ) );
	}

	public static function render_digest( array $d, $test = false ) {
		$worst = 'ok';
		foreach ( array( 'critical', 'high', 'medium' ) as $s ) {
			if ( $d['by'][ $s ] ) {
				$worst = $s;
				break;
			}
		}
		list( $fg, $bg, $bd ) = self::colors( $worst );
		$period = sprintf( /* translators: 1: from, 2: to */ __( '%1$s – %2$s', 'nightward' ), wp_date( 'j M, H:i', $d['since'] ), wp_date( 'j M, H:i' ) );
		if ( 'ok' === $worst ) {
			$headline = __( 'All clear', 'nightward' );
			$sub      = __( 'No new threats were detected since the last report. Monitors and scheduled checks are running.', 'nightward' );
		} else {
			$headline = 'critical' === $worst ? __( 'Action required', 'nightward' ) : ( 'high' === $worst ? __( 'Needs your attention', 'nightward' ) : __( 'Worth a look', 'nightward' ) );
			$sub      = __( 'New findings since the last report are listed below, most serious first.', 'nightward' );
		}
		$inner  = '';
		if ( $test ) {
			$inner .= '<tr><td style="padding:14px 28px 0;font-size:12px;color:#667085;">' . self::esc( __( 'Test message — the real report is sent automatically at the configured time.', 'nightward' ) ) . '</td></tr>';
		}
		$inner .= '<tr><td style="padding:20px 28px 8px;"><div style="background:' . $bg . ';border:1px solid ' . $bd . ';border-radius:10px;padding:16px 18px;">'
			. '<div style="font-size:12px;color:#667085;">' . self::esc( __( 'Daily security report', 'nightward' ) ) . ' · ' . self::esc( $period ) . '</div>'
			. '<div style="font-size:22px;font-weight:800;color:' . $fg . ';margin-top:4px;">' . self::esc( $headline ) . '</div>'
			. '<div style="font-size:14px;color:#344054;margin-top:4px;line-height:1.5;">' . self::esc( $sub ) . '</div></div></td></tr>';

		// Лічильники
		$inner .= '<tr><td style="padding:8px 22px 4px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="6"><tr>';
		foreach ( array( 'critical', 'high', 'medium', 'low' ) as $s ) {
			list( $sfg ) = self::colors( $s );
			$n = $d['by'][ $s ];
			$inner .= '<td width="25%" style="border:1px solid #eaecf0;border-radius:8px;padding:10px 12px;">'
				. '<div style="font-size:22px;font-weight:800;color:' . ( $n ? $sfg : '#98a2b3' ) . ';">' . (int) $n . '</div>'
				. '<div style="font-size:12px;color:#667085;">' . self::esc( Events::severity_label( $s ) ) . '</div></td>';
		}
		$inner .= '</tr></table></td></tr>';

		$open_bad = max( 0, $d['open']['critical'] + $d['open']['high'] - $d['by']['critical'] - $d['by']['high'] );
		if ( $open_bad ) {
			$inner .= '<tr><td style="padding:4px 28px 0;font-size:13px;color:#b42318;">'
				/* translators: %d: count */
				. self::esc( sprintf( _n( '%d critical/high issue is still open from earlier.', '%d critical/high issues are still open from earlier.', $open_bad, 'nightward' ), $open_bad ) ) . '</td></tr>';
		}

		// Події
		$important = array_filter( $d['events'], function ( $r ) {
			return Events::rank( $r->severity ) <= 1;
		} );
		$other = array_filter( $d['events'], function ( $r ) {
			return in_array( $r->severity, array( 'medium', 'low' ), true );
		} );
		if ( $important ) {
			$inner .= self::section( __( 'Needs attention', 'nightward' ) );
			foreach ( array_slice( $important, 0, 15 ) as $r ) {
				$dd     = Events::details( $r );
				$inner .= '<tr><td style="padding:10px 28px;border-bottom:1px solid #f2f4f7;">' . self::pill( $r->severity )
					. ' <span style="font-size:12px;color:#667085;">' . self::esc( Events::module_label( $r->module ) ) . '</span>'
					. '<div style="font-size:15px;font-weight:600;margin:6px 0 3px;"><a href="' . esc_url( admin_url( 'admin.php?page=nightward&tab=events&event=' . (int) $r->id ) ) . '" style="color:#101828;text-decoration:none;">' . self::esc( Events::title( $r ) ) . '</a></div>'
					. ( self::where( $r ) ? '<div style="font-size:12px;color:#475467;font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all;">' . self::esc( self::where( $r ) ) . '</div>' : '' )
					. ( ! empty( $dd['explanation'] ) ? '<div style="font-size:13px;color:#475467;margin-top:4px;line-height:1.5;">' . self::esc( Events::text( $dd['explanation'] ) ) . '</div>' : '' )
					. '</td></tr>';
			}
		}
		if ( $other ) {
			$inner .= self::section( __( 'Other findings', 'nightward' ) );
			$inner .= '<tr><td style="padding:4px 28px 8px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;">';
			foreach ( array_slice( $other, 0, 20 ) as $r ) {
				list( $sfg ) = self::colors( $r->severity );
				$inner .= '<tr><td style="padding:6px 0;border-bottom:1px solid #f2f4f7;width:14px;vertical-align:top;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' . $sfg . ';margin-top:5px;"></span></td>'
					. '<td style="padding:6px 0;border-bottom:1px solid #f2f4f7;color:#101828;">' . self::esc( Events::title( $r ) )
					. '<span style="color:#98a2b3;"> · ' . self::esc( Events::module_label( $r->module ) ) . '</span></td></tr>';
			}
			if ( count( $other ) > 20 ) {
				$inner .= '<tr><td></td><td style="padding:6px 0;color:#667085;">' . self::esc( sprintf( /* translators: %d: count */ __( '…and %d more in the dashboard.', 'nightward' ), count( $other ) - 20 ) ) . '</td></tr>';
			}
			$inner .= '</table></td></tr>';
		}

		// Нові хости
		$hosts = array_filter( (array) $d['hosts'], function ( $h ) {
			return ! Util::is_own_host( $h->host );
		} );
		if ( $hosts ) {
			$inner .= self::section( __( 'New outbound destinations', 'nightward' ) );
			$inner .= '<tr><td style="padding:4px 28px 8px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;">';
			foreach ( array_slice( $hosts, 0, 12 ) as $h ) {
				$inner .= '<tr><td style="padding:6px 0;border-bottom:1px solid #f2f4f7;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#101828;">' . self::esc( $h->host ) . '</td>'
					. '<td style="padding:6px 0;border-bottom:1px solid #f2f4f7;color:#475467;text-align:right;">' . self::esc( Attribution::label( $h->component ) ) . '</td></tr>';
			}
			$inner .= '</table></td></tr>';
		}

		// Стан перевірок
		$inner .= self::section( __( 'Checks', 'nightward' ) );
		$rows   = array();
		$int    = $d['integrity'];
		$rows[] = array(
			__( 'File integrity', 'nightward' ),
			is_array( $int )
				/* translators: 1: files, 2: time ago, 3: problems */
				? sprintf( _n( '%1$s files checked %2$s, %3$d problem', '%1$s files checked %2$s, %3$d problems', (int) $int['problems'], 'nightward' ), number_format_i18n( $int['files'] ), sprintf( __( '%s ago', 'nightward' ), human_time_diff( $int['finished'] ) ), $int['problems'] )
				: __( 'first scan pending', 'nightward' ),
		);
		$rows[] = array(
			__( 'Outbound requests', 'nightward' ),
			/* translators: 1: hosts, 2: intercepted */
			sprintf( __( '%1$d hosts contacted, %2$d responses faked', 'nightward' ), $d['net']['hosts'], $d['net']['intercepted'] ),
		);
		$rows[] = array( __( 'Hardening score', 'nightward' ), null === $d['hardening'] ? '—' : $d['hardening'] . ' / 100' );
		$c      = $d['cron'];
		$rows[] = array(
			__( 'Scheduled tasks', 'nightward' ),
			$c['stale'] ? __( 'NOT RUNNING — scans and reports may be delayed', 'nightward' ) : __( 'running', 'nightward' ),
		);
		$inner .= '<tr><td style="padding:4px 28px 10px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;">';
		foreach ( $rows as $r ) {
			$inner .= '<tr><td style="padding:6px 0;border-bottom:1px solid #f2f4f7;color:#667085;">' . self::esc( $r[0] ) . '</td><td style="padding:6px 0;border-bottom:1px solid #f2f4f7;text-align:right;color:#101828;">' . self::esc( $r[1] ) . '</td></tr>';
		}
		$inner .= '</table></td></tr>';
		$inner .= '<tr><td style="padding:14px 28px 24px;">' . self::button( admin_url( 'admin.php?page=nightward' ), __( 'Open Nightward', 'nightward' ) ) . '</td></tr>';
		return self::wrap( $inner, $headline . '. ' . $sub );
	}

	private static function section( $title ) {
		return '<tr><td style="padding:18px 28px 6px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:#667085;">' . self::esc( $title ) . '</td></tr>';
	}

	/* ------------------------------------------------------------------ */
	/* Transport                                                           */
	/* ------------------------------------------------------------------ */

	public static function site_name() {
		$n = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		return $n ? $n : wp_parse_url( home_url(), PHP_URL_HOST );
	}

	/** Render in the recipient's language when the recipient is a user of this site. */
	private static function with_locale( callable $fn ) {
		$to     = Settings::report_email();
		$first  = trim( (string) strtok( $to, ',' ) );
		$user   = $first ? get_user_by( 'email', $first ) : null;
		$locale = $user ? get_user_locale( $user ) : get_locale();
		$cur    = determine_locale();
		if ( $locale === $cur ) {
			return $fn();
		}
		// switch_to_locale() works only for installed core languages; our own .mo is loaded regardless.
		$sw = function_exists( 'switch_to_locale' ) && switch_to_locale( $locale );
		self::load_domain( $locale );
		$out = $fn();
		if ( $sw ) {
			restore_previous_locale();
		}
		self::load_domain( $cur );
		return $out;
	}

	private static function load_domain( $locale ) {
		unload_textdomain( 'nightward' );
		foreach ( array( WP_LANG_DIR . '/plugins/nightward-' . $locale . '.mo', NIGHTWARD_DIR . 'languages/nightward-' . $locale . '.mo' ) as $mo ) {
			if ( is_readable( $mo ) ) {
				load_textdomain( 'nightward', $mo, $locale );
				return;
			}
		}
	}

	private static function mail( $subject, $html, $to = '' ) {
		$to = $to ? $to : Settings::report_email();
		if ( ! $to ) {
			return false;
		}
		self::$mail_error = '';
		$catch = function ( $err ) {
			self::$mail_error = $err instanceof \WP_Error ? $err->get_error_message() : 'unknown';
		};
		$alt = function ( $phpmailer ) use ( $html ) {
			$phpmailer->AltBody = trim( html_entity_decode( wp_strip_all_tags( preg_replace( array( '#<br\s*/?>#i', '#</(div|tr|p|h\d)>#i' ), "\n", $html ) ), ENT_QUOTES, 'UTF-8' ) );
		};
		add_action( 'wp_mail_failed', $catch );
		add_action( 'phpmailer_init', $alt );
		$ok = wp_mail( array_map( 'trim', explode( ',', $to ) ), $subject, $html, array( 'Content-Type: text/html; charset=UTF-8' ) );
		remove_action( 'wp_mail_failed', $catch );
		remove_action( 'phpmailer_init', $alt );
		global $phpmailer;
		if ( is_object( $phpmailer ) && property_exists( $phpmailer, 'AltBody' ) ) {
			$phpmailer->AltBody = ''; // не лишати наш текст наступним листам інших плагінів
		}
		update_option( 'nightward_mail_status', array( 'ok' => (bool) $ok, 'at' => time(), 'error' => self::$mail_error, 'subject' => $subject ), false );
		return (bool) $ok;
	}
}
