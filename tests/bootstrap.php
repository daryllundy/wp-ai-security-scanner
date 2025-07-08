<?php
/**
 * PHPUnit bootstrap file for WP AI Security Scanner tests
 */

// Load WordPress test environment
$_tests_dir = getenv('WP_TESTS_DIR');
if (!$_tests_dir) {
    $_tests_dir = '/tmp/wordpress-tests-lib';
}

require_once $_tests_dir . '/includes/functions.php';

/**
 * Manually load the plugin being tested
 */
function _manually_load_plugin() {
    require dirname(__FILE__) . '/../wp-ai-security-scanner.php';
}
tests_add_filter('muplugins_loaded', '_manually_load_plugin');

/**
 * Load the WordPress test suite
 */
require $_tests_dir . '/includes/bootstrap.php';

/**
 * Load plugin classes for testing
 */
require_once dirname(__FILE__) . '/../includes/class-database.php';
require_once dirname(__FILE__) . '/../includes/class-scanner.php';
require_once dirname(__FILE__) . '/../includes/class-malware-detector.php';
require_once dirname(__FILE__) . '/../includes/class-admin.php';
require_once dirname(__FILE__) . '/../includes/class-security-features.php';