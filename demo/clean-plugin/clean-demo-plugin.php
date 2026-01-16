<?php
/*
Plugin Name: Clean Demo Plugin
Description: Safe reference plugin for demo scans.
Version: 1.0.0
Author: Demo
*/

if (!defined('ABSPATH')) {
    exit;
}

function wp_ai_clean_demo_notice() {
    echo '<div class="notice notice-info"><p>Clean Demo Plugin active.</p></div>';
}

add_action('admin_notices', 'wp_ai_clean_demo_notice');
