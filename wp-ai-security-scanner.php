<?php
/**
 * Plugin Name: WordPress AI Security Scanner
 * Description: AI-powered WordPress security scanner with intelligent threat detection and automated remediation
 * Version: 1.0.0
 * Author: Daryl Lundy
 * License: GPL v2 or later
 * Text Domain: wp-ai-security-scanner
 */

if (!defined('ABSPATH')) {
    exit;
}

define('WP_AI_SECURITY_SCANNER_VERSION', '1.0.0');
define('WP_AI_SECURITY_SCANNER_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('WP_AI_SECURITY_SCANNER_PLUGIN_URL', plugin_dir_url(__FILE__));

class WP_AI_Security_Scanner {
    
    private static $instance = null;
    
    public static function get_instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        add_action('plugins_loaded', array($this, 'init'));
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
        register_uninstall_hook(__FILE__, array('WP_AI_Security_Scanner', 'uninstall'));
    }
    
    public function init() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        $this->load_dependencies();
        $this->init_hooks();
    }
    
    private function load_dependencies() {
        require_once WP_AI_SECURITY_SCANNER_PLUGIN_DIR . 'includes/class-database.php';
        require_once WP_AI_SECURITY_SCANNER_PLUGIN_DIR . 'includes/class-scanner.php';
        require_once WP_AI_SECURITY_SCANNER_PLUGIN_DIR . 'includes/class-malware-detector.php';
        require_once WP_AI_SECURITY_SCANNER_PLUGIN_DIR . 'includes/class-admin.php';
        require_once WP_AI_SECURITY_SCANNER_PLUGIN_DIR . 'includes/class-security-features.php';
    }
    
    private function init_hooks() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('wp_ajax_start_scan', array($this, 'ajax_start_scan'));
        add_action('wp_ajax_get_scan_progress', array($this, 'ajax_get_scan_progress'));
        add_action('wp_ajax_test_openai_key', array($this, 'ajax_test_openai_key'));
        add_action('wp_ajax_test_virustotal_key', array($this, 'ajax_test_virustotal_key'));
    }
    
    public function add_admin_menu() {
        add_menu_page(
            'WordPress AI Security Scanner',
            'AI Security Scanner',
            'manage_options',
            'wp-ai-security-scanner',
            array($this, 'admin_page'),
            'dashicons-shield-alt',
            30
        );
        
        add_submenu_page(
            'wp-ai-security-scanner',
            'Dashboard',
            'Dashboard',
            'manage_options',
            'wp-ai-security-scanner',
            array($this, 'admin_page')
        );
        
        add_submenu_page(
            'wp-ai-security-scanner',
            'Scan Results',
            'Scan Results',
            'manage_options',
            'wp-ai-security-scanner-results',
            array($this, 'results_page')
        );
        
        add_submenu_page(
            'wp-ai-security-scanner',
            'Settings',
            'Settings',
            'manage_options',
            'wp-ai-security-scanner-settings',
            array($this, 'settings_page')
        );
    }
    
    public function enqueue_admin_scripts($hook) {
        if (strpos($hook, 'wp-ai-security-scanner') !== false) {
            wp_enqueue_script('wp-ai-security-scanner-admin', WP_AI_SECURITY_SCANNER_PLUGIN_URL . 'assets/js/admin.js', array('jquery'), WP_AI_SECURITY_SCANNER_VERSION, true);
            wp_enqueue_style('wp-ai-security-scanner-admin', WP_AI_SECURITY_SCANNER_PLUGIN_URL . 'assets/css/admin.css', array(), WP_AI_SECURITY_SCANNER_VERSION);
            
            wp_localize_script('wp-ai-security-scanner-admin', 'wpAiScannerAjax', array(
                'ajax_url' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('wp_ai_scanner_nonce')
            ));
        }
    }
    
    public function admin_page() {
        $admin = new WP_AI_Security_Scanner_Admin();
        $admin->display_dashboard();
    }
    
    public function results_page() {
        $admin = new WP_AI_Security_Scanner_Admin();
        $admin->display_results();
    }
    
    public function settings_page() {
        $admin = new WP_AI_Security_Scanner_Admin();
        $admin->display_settings();
    }
    
    public function ajax_start_scan() {
        check_ajax_referer('wp_ai_scanner_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        
        $scanner = new WP_AI_Security_Scanner_Scanner();
        $result = $scanner->start_scan();
        
        wp_send_json_success($result);
    }
    
    public function ajax_get_scan_progress() {
        check_ajax_referer('wp_ai_scanner_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        
        $scanner = new WP_AI_Security_Scanner_Scanner();
        $progress = $scanner->get_scan_progress();
        
        wp_send_json_success($progress);
    }
    
    public function ajax_test_openai_key() {
        check_ajax_referer('wp_ai_scanner_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        
        $api_key = sanitize_text_field($_POST['api_key']);
        
        if (empty($api_key)) {
            wp_send_json_error('API key is required');
        }
        
        if (!class_exists('WP_AI_Security_Scanner_Malware_Detector')) {
            wp_send_json_error('Malware detector class not found');
        }
        
        $detector = new WP_AI_Security_Scanner_Malware_Detector();
        $is_valid = $detector->validate_openai_api_key($api_key);
        
        if ($is_valid) {
            wp_send_json_success('OpenAI API key is valid');
        } else {
            wp_send_json_error('Invalid OpenAI API key');
        }
    }
    
    public function ajax_test_virustotal_key() {
        check_ajax_referer('wp_ai_scanner_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        
        $api_key = sanitize_text_field($_POST['api_key']);
        
        if (empty($api_key)) {
            wp_send_json_error('API key is required');
        }
        
        if (!class_exists('WP_AI_Security_Scanner_Malware_Detector')) {
            wp_send_json_error('Malware detector class not found');
        }
        
        $detector = new WP_AI_Security_Scanner_Malware_Detector();
        $is_valid = $detector->validate_virustotal_api_key($api_key);
        
        if ($is_valid) {
            wp_send_json_success('VirusTotal API key is valid');
        } else {
            wp_send_json_error('Invalid VirusTotal API key');
        }
    }
    
    public function activate() {
        $database = new WP_AI_Security_Scanner_Database();
        $database->create_tables();
        
        add_option('wp_ai_security_scanner_version', WP_AI_SECURITY_SCANNER_VERSION);
        
        $default_settings = array(
            'scan_paths' => array(ABSPATH),
            'file_extensions' => array('php', 'js', 'html', 'htm', 'css'),
            'max_file_size' => 10485760, // 10MB
            'email_notifications' => true,
            'notification_email' => get_option('admin_email'),
            'scan_frequency' => 'daily',
            'use_openai' => false,
            'openai_api_key' => '',
            'use_virustotal' => false,
            'virustotal_api_key' => ''
        );
        
        add_option('wp_ai_security_scanner_settings', $default_settings);
        
        if (!wp_next_scheduled('wp_ai_security_scanner_cron')) {
            wp_schedule_event(time(), 'daily', 'wp_ai_security_scanner_cron');
        }
    }
    
    public function deactivate() {
        wp_clear_scheduled_hook('wp_ai_security_scanner_cron');
    }
    
    public static function uninstall() {
        global $wpdb;
        
        $tables = array(
            $wpdb->prefix . 'ai_scanner_results',
            $wpdb->prefix . 'ai_scanner_config',
            $wpdb->prefix . 'ai_scanner_quarantine'
        );
        
        foreach ($tables as $table) {
            $wpdb->query("DROP TABLE IF EXISTS $table");
        }
        
        delete_option('wp_ai_security_scanner_version');
        delete_option('wp_ai_security_scanner_settings');
        delete_option('wp_ai_security_scanner_last_scan');
        delete_option('wp_ai_security_scanner_scan_progress');
    }
}

WP_AI_Security_Scanner::get_instance();