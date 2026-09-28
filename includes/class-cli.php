<?php
/**
 * WP-CLI: wp nightward export
 */

namespace Nightward;

defined( 'ABSPATH' ) || exit;

class CLI {

	/**
	 * Export findings and site context for analysis by an AI assistant.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : md (Markdown, best for chat) or json.
	 * ---
	 * default: md
	 * options:
	 *   - md
	 *   - json
	 * ---
	 *
	 * [--days=<days>]
	 * : Findings seen in the last N days. 0 = all time.
	 * ---
	 * default: 30
	 * ---
	 *
	 * [--all]
	 * : Include resolved and ignored findings.
	 *
	 * [--min-severity=<severity>]
	 * : critical, high, medium, low or info.
	 * ---
	 * default: low
	 * ---
	 *
	 * [--no-inventory]
	 * : Leave out plugins, outbound hosts, hooks and scheduled tasks.
	 *
	 * [--no-redact]
	 * : Keep the real site address, e-mail and IP addresses.
	 *
	 * [--file=<path>]
	 * : Write to this file instead of standard output.
	 *
	 * ## EXAMPLES
	 *
	 *     wp nightward export > nightward.md
	 *     wp nightward export --format=json --days=7 --file=report.json
	 *
	 * @when after_wp_load
	 */
	public function export( $args, $assoc ) {
		$opt = Export::sanitize( array(
			'format'       => isset( $assoc['format'] ) ? $assoc['format'] : 'md',
			'days'         => isset( $assoc['days'] ) ? $assoc['days'] : 30,
			'status'       => ! empty( $assoc['all'] ) ? 'all' : 'active',
			'min_severity' => isset( $assoc['min-severity'] ) ? $assoc['min-severity'] : 'low',
			'inventory'    => ! ( isset( $assoc['inventory'] ) && false === $assoc['inventory'] ),
			'redact'       => ! ( isset( $assoc['redact'] ) && false === $assoc['redact'] ),
		) );
		$text = Export::render( Export::build( $opt ), $opt['format'] );
		if ( ! empty( $assoc['file'] ) ) {
			if ( false === file_put_contents( $assoc['file'], $text ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
				\WP_CLI::error( 'Cannot write ' . $assoc['file'] );
			}
			\WP_CLI::success( 'Written ' . $assoc['file'] . ' (' . size_format( strlen( $text ) ) . ').' );
			return;
		}
		echo $text; // phpcs:ignore WordPress.Security.EscapeOutput
	}
}
