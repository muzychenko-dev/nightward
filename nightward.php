<?php
/**
 * Plugin Name:       Nightward
 * Plugin URI:        https://nightward.muzychenko.dev
 * Description:       Runtime security monitor: sees what plugins and themes actually do — outbound requests, faked HTTP responses, new hooks on login and capability checks, administrators created from code, file changes in premium plugins — and emails you a daily report.
 * Version:           1.1.2
 * Requires at least: 6.2
 * Requires PHP:      7.4
 * Author:            Ihor Muzychenko
 * Author URI:        https://muzychenko.dev
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       nightward
 * Domain Path:       /languages
 * Update URI:        https://nightward.muzychenko.dev
 */

defined( 'ABSPATH' ) || exit;

// Ранній завантажувач у mu-plugins міг уже підняти монітори — тоді bootstrap
// не повторюється, але хуки активації/деактивації реєструються завжди.
if ( ! defined( 'NIGHTWARD_VERSION' ) ) {
	define( 'NIGHTWARD_FILE', __FILE__ );
	require_once __DIR__ . '/includes/bootstrap.php';
}

register_activation_hook( __FILE__, array( 'Nightward\\Installer', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Nightward\\Installer', 'deactivate' ) );

Nightward\Plugin::instance()->boot( 'plugin' );
