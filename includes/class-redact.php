<?php
/**
 * Credentials never reach the database. Every URL and free-text detail is passed
 * through here before it is stored: bot tokens, webhook secrets, basic-auth
 * passwords and secret query values become "…". Hosts, paths and IDs stay,
 * because attribution and investigation need them.
 *
 * Idempotent: masking an already masked string changes nothing.
 */

namespace Nightward;

defined( 'ABSPATH' ) || exit;

class Redact {

	const MASK = '…';

	/** Query keys whose values are secrets. Matched as whole parameter names. */
	public static function secret_keys() {
		return array(
			'token', 'key', 'api_key', 'apikey', 'api-key', 'x-api-key', 'secret', 'client_secret', 'password', 'passwd',
			'pass', 'pwd', 'auth', 'authorization', 'access_token', 'refresh_token', 'id_token', 'auth_token',
			'sig', 'signature', 'license', 'license_key', 'licence', 'licence_key', 'purchase_code', 'private_key',
			'session', 'sessionid', 'hash', 'nonce',
		);
	}

	/** A single URL. Same rules as text(); kept separate for readability at call sites. */
	public static function url( $url ) {
		return self::text( (string) $url );
	}

	/** Mask credentials anywhere in a string (URLs inside JSON, cron arguments, messages). */
	public static function text( $s ) {
		if ( ! is_string( $s ) || '' === $s ) {
			return $s;
		}
		$m = self::MASK;
		// user:pass@host in any URL.
		$s = preg_replace( '#\b([a-z][a-z0-9+.\-]*://)[^/@\s?\#"\'<>]+@#i', '$1' . $m . '@', $s );
		// Telegram Bot API: /bot<id>:<secret> - the bot ID stays.
		$s = preg_replace( '#(/bot\d{3,15}):[A-Za-z0-9_\-]+#', '$1:' . $m, $s );
		// Bare Telegram tokens outside URLs (cron args, options).
		$s = preg_replace( '#\b(\d{6,15}):AA[A-Za-z0-9_\-]{20,}#', '$1:' . $m, $s );
		// Discord webhooks: /api/webhooks/<id>/<token>.
		$s = preg_replace( '#(/api/webhooks/\d+/)[A-Za-z0-9_.\-]+#i', '$1' . $m, $s );
		// Slack webhooks: hooks.slack.com/services/T…/B…/<secret>.
		$s = preg_replace( '#(hooks\.slack\.com/services/[^/\s"\']+/[^/\s"\']+/)[A-Za-z0-9]+#i', '$1' . $m, $s );
		// Secret query values (and the same keys in JSON-encoded query strings: & / &amp;).
		$keys = implode( '|', array_map( function ( $k ) {
			return preg_quote( $k, '#' );
		}, self::secret_keys() ) );
		$s = preg_replace( '#([?&;]|&amp;|\\\\u0026)(' . $keys . ')=(?!' . preg_quote( $m, '#' ) . '(?:[&\#\s"\']|$))[^&\#\s"\'<>]*#i', '$1$2=' . $m, $s );
		return $s;
	}

	/** Recursively mask every string in an array (event details). */
	public static function deep( $v ) {
		if ( is_string( $v ) ) {
			return self::text( $v );
		}
		if ( is_array( $v ) ) {
			foreach ( $v as $k => $x ) {
				$v[ $k ] = self::deep( $x );
			}
		}
		return $v;
	}

	/* ------------------------------------------------------------------ */
	/* One-time clean-up of rows written before 1.1.7                      */
	/* ------------------------------------------------------------------ */

	const MIGRATION = 'nightward_redact_migration';

	public static function migration_done() {
		$st = get_option( self::MIGRATION );
		return is_array( $st ) && ! empty( $st['done'] );
	}

	/**
	 * Clean event details and titles in batches, then the outbound hosts table.
	 * Safe to interrupt: progress is stored after every batch and the next
	 * admin request continues.
	 *
	 * @return bool true when everything has been processed
	 */
	public static function migrate( $batch = 500, $budget = 10 ) {
		global $wpdb;
		if ( self::migration_done() || ! DB::ready() ) {
			return true;
		}
		$st    = get_option( self::MIGRATION );
		$st    = is_array( $st ) ? $st : array( 'last_id' => 0, 'done' => false, 'changed' => 0 );
		$t     = DB::events();
		$start = microtime( true );
		do {
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, title, details FROM {$t} WHERE id > %d ORDER BY id ASC LIMIT %d", (int) $st['last_id'], (int) $batch ) ); // phpcs:ignore
			foreach ( $rows as $r ) {
				$title   = self::text( (string) $r->title );
				$decoded = json_decode( (string) $r->details, true );
				$details = is_array( $decoded )
					? wp_json_encode( self::deep( $decoded ), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR )
					: self::text( (string) $r->details );
				if ( $title !== $r->title || $details !== $r->details ) {
					$wpdb->update( $t, array( 'title' => $title, 'details' => $details ), array( 'id' => (int) $r->id ) );
					$st['changed']++;
				}
				$st['last_id'] = (int) $r->id;
			}
			update_option( self::MIGRATION, $st, false );
		} while ( $rows && count( $rows ) === (int) $batch && microtime( true ) - $start < $budget );

		if ( $rows && count( $rows ) === (int) $batch ) {
			return false; // more to do on the next request
		}
		$e = DB::egress();
		foreach ( (array) $wpdb->get_results( "SELECT id, sample_url FROM {$e} WHERE sample_url <> ''" ) as $r ) { // phpcs:ignore
			$clean = self::url( (string) $r->sample_url );
			if ( $clean !== $r->sample_url ) {
				$wpdb->update( $e, array( 'sample_url' => $clean ), array( 'id' => (int) $r->id ) );
				$st['changed']++;
			}
		}
		$st['done'] = true;
		$st['at']   = time();
		update_option( self::MIGRATION, $st, false );
		return true;
	}
}
