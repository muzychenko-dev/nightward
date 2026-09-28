<?php
/**
 * Cron Guard: scheduled tasks are a favourite persistence spot — a backdoor
 * deleted from disk comes back from an event that re-downloads it.
 *
 * - new hooks after the learning period (with the component whose callback runs it);
 * - random-looking hook names;
 * - arguments carrying code, base64 blobs or URLs;
 * - orphaned hooks (nothing will run them — clutter left by removed plugins);
 * - overdue queue (WP-Cron is not running).
 */

namespace Nightward\Monitor;

use Nightward\Attribution;
use Nightward\Events;
use Nightward\Settings;

defined( 'ABSPATH' ) || exit;

class Cron_Guard {

	const KNOWN = 'nightward_cron_known';

	/** @return array hook => array( 'count', 'next', 'schedule', 'args' (first) ) */
	public static function inventory() {
		$out  = array();
		$cron = function_exists( '_get_cron_array' ) ? _get_cron_array() : array();
		foreach ( (array) $cron as $ts => $hooks ) {
			foreach ( (array) $hooks as $hook => $events ) {
				foreach ( (array) $events as $ev ) {
					if ( ! isset( $out[ $hook ] ) ) {
						$out[ $hook ] = array( 'count' => 0, 'next' => (int) $ts, 'schedule' => isset( $ev['schedule'] ) ? $ev['schedule'] : false, 'args' => isset( $ev['args'] ) ? $ev['args'] : array() );
					}
					$out[ $hook ]['count']++;
				}
			}
		}
		return $out;
	}

	public static function random_name( $hook ) {
		$h = strtolower( $hook );
		if ( preg_match( '/^[a-f0-9]{12,}$/', $h ) || preg_match( '/^[a-z0-9]{24,}$/', $h ) && ! preg_match( '/[aeiou]{1}[a-z]{2,}[aeiou]/', $h ) ) {
			return true;
		}
		// Мало голосних на довгому імені без розділювачів — теж випадковий рядок.
		if ( strlen( $h ) >= 16 && false === strpbrk( $h, '_-.' ) ) {
			$v = preg_match_all( '/[aeiou]/', $h );
			return $v / strlen( $h ) < 0.15;
		}
		return false;
	}

	public static function bad_args( $args ) {
		$flat = wp_json_encode( $args );
		if ( ! $flat || '[]' === $flat ) {
			return '';
		}
		if ( preg_match( '/<\?php|eval\s*\(|base64_decode|gzinflate|str_rot13|assert\s*\(|system\s*\(|shell_exec/i', $flat ) ) {
			return __( 'arguments contain PHP code', 'nightward' );
		}
		if ( preg_match( '/[A-Za-z0-9+\/]{200,}={0,2}/', $flat ) ) {
			return __( 'arguments contain a long base64 blob', 'nightward' );
		}
		if ( preg_match( '#https?:\\\\?/\\\\?/[^"]+\.(php|txt|zip|jpg|png)#i', $flat ) ) {
			return __( 'arguments contain a URL to a file', 'nightward' );
		}
		return '';
	}

	public static function check() {
		$inv      = self::inventory();
		$known    = get_option( self::KNOWN, null );
		$first    = ! is_array( $known );
		$known    = $first ? array() : $known;
		$learning = Settings::in_learning() || $first;
		$changed  = false;
		$overdue  = 0;

		foreach ( $inv as $hook => $info ) {
			if ( $info['next'] < time() - HOUR_IN_SECONDS ) {
				$overdue++;
			}
			$cb   = self::callback_of( $hook );
			$args = self::bad_args( $info['args'] );
			if ( $args ) {
				self::event( $hook, $info, $cb, 'critical', 'bad_args',
					/* translators: %s: reason */
					array( __( 'Scheduled task %s', 'nightward' ), $args ) );
			}
			if ( isset( $known[ $hook ] ) ) {
				continue;
			}
			$known[ $hook ] = time();
			$changed        = true;
			if ( 0 === strpos( $hook, 'nightward_' ) ) {
				continue;
			}
			$random = self::random_name( $hook );
			if ( $random ) {
				self::event( $hook, $info, $cb, 'high', 'random_name', __( 'The task name looks random. Malware generates such names so that each infection looks different.', 'nightward' ) );
				continue;
			}
			if ( $learning ) {
				continue;
			}
			$sev = 'eval' === $cb['component'] ? 'critical' : ( 'none' === $cb['component'] ? 'low' : 'info' );
			self::event( $hook, $info, $cb, $sev, 'new_hook', 'none' === $cb['component']
				? __( 'New scheduled task, but no code is attached to it in this request.', 'nightward' )
				: __( 'New scheduled task.', 'nightward' ) );
		}
		if ( $changed || $first ) {
			// Прибрати зниклі, щоб таблиця не росла вічно.
			$known = array_intersect_key( $known, $inv );
			update_option( self::KNOWN, $known, false );
		}
		update_option( 'nightward_cron_stats', array( 'hooks' => count( $inv ), 'overdue' => $overdue, 'at' => time() ), false );
	}

	/** First non-core callback on a cron hook, or 'none' when nothing listens. */
	public static function callback_of( $hook ) {
		global $wp_filter;
		if ( empty( $wp_filter[ $hook ] ) || ! ( $wp_filter[ $hook ] instanceof \WP_Hook ) || ! $wp_filter[ $hook ]->callbacks ) {
			return array( 'component' => 'none', 'file' => '', 'line' => 0, 'name' => '' );
		}
		$first = null;
		foreach ( $wp_filter[ $hook ]->callbacks as $cbs ) {
			foreach ( $cbs as $cb ) {
				$info = Attribution::callback_info( $cb['function'] );
				if ( null === $first ) {
					$first = $info;
				}
				if ( 'core' !== $info['component'] ) {
					return $info;
				}
			}
		}
		return $first;
	}

	private static function event( $hook, $info, $cb, $sev, $type, $why ) {
		Events::record( array(
			'module'    => 'cron',
			'type'      => $type,
			'severity'  => $sev,
			/* translators: 1: hook name, 2: plugin name */
			'title'     => 'none' === $cb['component']
				/* translators: %s: hook name */
				? array( __( 'Scheduled task %s (no handler)', 'nightward' ), $hook )
				: array( __( 'Scheduled task %1$s → %2$s', 'nightward' ), $hook, Attribution::label( $cb['component'] ) ),
			'details'   => array(
				'explanation' => $why,
				'hook'        => $hook,
				'recurrence'  => $info['schedule'] ? $info['schedule'] : __( 'single', 'nightward' ),
				'next_run'    => wp_date( 'Y-m-d H:i', $info['next'] ),
				'instances'   => $info['count'],
				'handler'     => $cb['name'],
				'args'        => mb_substr( (string) wp_json_encode( $info['args'] ), 0, 300 ),
			),
			'component' => 'none' === $cb['component'] ? '' : $cb['component'],
			'file'      => $cb['file'],
			'line'      => $cb['line'],
			'key'       => 'cron|' . $type . '|' . $hook,
		) );
	}

	/** For the admin screen. */
	public static function table() {
		$rows = array();
		foreach ( self::inventory() as $hook => $info ) {
			$cb     = self::callback_of( $hook );
			$rows[] = array(
				'hook'      => $hook,
				'next'      => $info['next'],
				'schedule'  => $info['schedule'],
				'count'     => $info['count'],
				'component' => $cb['component'],
				'handler'   => $cb['name'],
				'file'      => $cb['file'],
				'line'      => $cb['line'],
				'random'    => self::random_name( $hook ),
				'bad_args'  => self::bad_args( $info['args'] ),
			);
		}
		usort( $rows, function ( $a, $b ) {
			return $a['next'] - $b['next'];
		} );
		return $rows;
	}
}
