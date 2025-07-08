<?php

if (!defined('ABSPATH')) {
    exit;
}

class WP_AI_Security_Scanner_Security_Features {
    
    private $database;
    private $quarantine_dir;
    
    public function __construct() {
        $this->database = new WP_AI_Security_Scanner_Database();
        $this->quarantine_dir = WP_CONTENT_DIR . '/ai-scanner-quarantine/';
        
        $this->init_hooks();
        $this->ensure_quarantine_dir();
    }
    
    private function init_hooks() {
        add_action('wp_ajax_quarantine_file', array($this, 'ajax_quarantine_file'));
        add_action('wp_ajax_ignore_threat', array($this, 'ajax_ignore_threat'));
        add_action('wp_ajax_get_threat_stats', array($this, 'ajax_get_threat_stats'));
        add_action('wp_ajax_cancel_scan', array($this, 'ajax_cancel_scan'));
        add_action('wp_ai_security_scanner_cron', array($this, 'scheduled_scan'));
    }
    
    private function ensure_quarantine_dir() {
        if (!file_exists($this->quarantine_dir)) {
            wp_mkdir_p($this->quarantine_dir);
        }
        
        $htaccess_content = "Order deny,allow\nDeny from all\n";
        file_put_contents($this->quarantine_dir . '.htaccess', $htaccess_content);
        
        $index_content = "<?php\n// Silence is golden\n";
        file_put_contents($this->quarantine_dir . 'index.php', $index_content);
    }
    
    public function quarantine_file($file_path, $reason = '') {
        if (!file_exists($file_path)) {
            return new WP_Error('file_not_found', 'File not found: ' . $file_path);
        }
        
        if (!is_readable($file_path)) {
            return new WP_Error('file_not_readable', 'File is not readable: ' . $file_path);
        }
        
        $original_content = file_get_contents($file_path);
        if ($original_content === false) {
            return new WP_Error('read_error', 'Could not read file: ' . $file_path);
        }
        
        $quarantine_filename = $this->generate_quarantine_filename($file_path);
        $quarantine_path = $this->quarantine_dir . $quarantine_filename;
        
        if (!file_put_contents($quarantine_path, $original_content)) {
            return new WP_Error('quarantine_error', 'Could not create quarantine file');
        }
        
        $replacement_content = $this->generate_replacement_content($file_path, $reason);
        
        if (!file_put_contents($file_path, $replacement_content)) {
            unlink($quarantine_path);
            return new WP_Error('replacement_error', 'Could not replace original file');
        }
        
        $this->database->quarantine_file($file_path, $original_content, $quarantine_path, $reason);
        
        $this->send_quarantine_notification($file_path, $reason);
        
        return true;
    }
    
    private function generate_quarantine_filename($file_path) {
        $filename = basename($file_path);
        $timestamp = date('Y-m-d_H-i-s');
        $hash = substr(md5($file_path), 0, 8);
        
        return "{$timestamp}_{$hash}_{$filename}";
    }
    
    private function generate_replacement_content($file_path, $reason) {
        $site_name = get_bloginfo('name');
        $admin_email = get_option('admin_email');
        $timestamp = date('Y-m-d H:i:s');
        
        $content = "<?php\n";
        $content .= "/**\n";
        $content .= " * QUARANTINED FILE - {$site_name}\n";
        $content .= " * \n";
        $content .= " * This file has been quarantined by WordPress AI Security Scanner\n";
        $content .= " * Original file: {$file_path}\n";
        $content .= " * Quarantined: {$timestamp}\n";
        $content .= " * Reason: {$reason}\n";
        $content .= " * \n";
        $content .= " * Contact: {$admin_email}\n";
        $content .= " * \n";
        $content .= " * To restore this file, please log into your WordPress admin panel\n";
        $content .= " * and use the WordPress AI Security Scanner plugin.\n";
        $content .= " */\n\n";
        $content .= "// File has been quarantined for security reasons\n";
        $content .= "wp_die('This file has been quarantined by WordPress AI Security Scanner for security reasons. Please contact your administrator.');\n";
        
        return $content;
    }
    
    public function restore_file($file_path) {
        $quarantined_files = $this->database->get_quarantined_files();
        
        foreach ($quarantined_files as $quarantined_file) {
            if ($quarantined_file->file_path === $file_path) {
                if (!file_exists($quarantined_file->backup_path)) {
                    return new WP_Error('backup_not_found', 'Quarantined backup not found');
                }
                
                $original_content = file_get_contents($quarantined_file->backup_path);
                if ($original_content === false) {
                    return new WP_Error('backup_read_error', 'Could not read quarantined backup');
                }
                
                if (!file_put_contents($file_path, $original_content)) {
                    return new WP_Error('restore_error', 'Could not restore original file');
                }
                
                global $wpdb;
                $wpdb->update(
                    $wpdb->prefix . 'ai_scanner_quarantine',
                    array('restored_at' => current_time('mysql')),
                    array('id' => $quarantined_file->id),
                    array('%s'),
                    array('%d')
                );
                
                unlink($quarantined_file->backup_path);
                
                return true;
            }
        }
        
        return new WP_Error('file_not_quarantined', 'File is not quarantined');
    }
    
    public function clean_file($file_path, $threat_patterns) {
        if (!file_exists($file_path)) {
            return new WP_Error('file_not_found', 'File not found: ' . $file_path);
        }
        
        $original_content = file_get_contents($file_path);
        if ($original_content === false) {
            return new WP_Error('read_error', 'Could not read file: ' . $file_path);
        }
        
        $backup_path = $this->quarantine_dir . 'backup_' . $this->generate_quarantine_filename($file_path);
        file_put_contents($backup_path, $original_content);
        
        $cleaned_content = $original_content;
        
        foreach ($threat_patterns as $pattern) {
            $cleaned_content = preg_replace($pattern, '', $cleaned_content);
        }
        
        if ($cleaned_content !== $original_content) {
            if (!file_put_contents($file_path, $cleaned_content)) {
                return new WP_Error('write_error', 'Could not write cleaned file');
            }
            
            $this->send_cleaning_notification($file_path, count($threat_patterns));
            
            return true;
        }
        
        return new WP_Error('no_changes', 'No threats found to clean');
    }
    
    public function ajax_quarantine_file() {
        check_ajax_referer('wp_ai_scanner_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        
        $threat_id = intval($_POST['threat_id']);
        
        global $wpdb;
        $threat = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}ai_scanner_results WHERE id = %d",
            $threat_id
        ));
        
        if (!$threat) {
            wp_send_json_error('Threat not found');
        }
        
        $result = $this->quarantine_file($threat->file_path, $threat->threat_description);
        
        if (is_wp_error($result)) {
            wp_send_json_error($result->get_error_message());
        }
        
        $this->database->update_threat_status($threat_id, 'quarantined');
        
        wp_send_json_success('File quarantined successfully');
    }
    
    public function ajax_ignore_threat() {
        check_ajax_referer('wp_ai_scanner_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        
        $threat_id = intval($_POST['threat_id']);
        
        $result = $this->database->update_threat_status($threat_id, 'ignored');
        
        if ($result) {
            wp_send_json_success('Threat ignored successfully');
        } else {
            wp_send_json_error('Failed to ignore threat');
        }
    }
    
    public function ajax_get_threat_stats() {
        check_ajax_referer('wp_ai_scanner_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        
        $stats = $this->database->get_threat_statistics();
        wp_send_json_success($stats);
    }
    
    public function ajax_cancel_scan() {
        check_ajax_referer('wp_ai_scanner_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        
        $scanner = new WP_AI_Security_Scanner_Scanner();
        $result = $scanner->cancel_scan();
        
        if ($result) {
            wp_send_json_success('Scan cancelled successfully');
        } else {
            wp_send_json_error('Failed to cancel scan');
        }
    }
    
    public function scheduled_scan() {
        $scanner = new WP_AI_Security_Scanner_Scanner();
        $result = $scanner->start_scan();
        
        if (!empty($result['threats_found']) && $result['threats_found'] > 0) {
            $this->send_scheduled_scan_notification($result);
        }
        
        $this->cleanup_old_scans();
    }
    
    private function cleanup_old_scans() {
        global $wpdb;
        
        $wpdb->query(
            "DELETE FROM {$wpdb->prefix}ai_scanner_results 
             WHERE detected_at < DATE_SUB(NOW(), INTERVAL 30 DAY) 
             AND status = 'ignored'"
        );
        
        $wpdb->query(
            "DELETE FROM {$wpdb->prefix}ai_scanner_quarantine 
             WHERE quarantined_at < DATE_SUB(NOW(), INTERVAL 90 DAY) 
             AND restored_at IS NOT NULL"
        );
    }
    
    private function send_quarantine_notification($file_path, $reason) {
        $settings = get_option('wp_ai_security_scanner_settings', array());
        
        if (empty($settings['email_notifications']) || empty($settings['notification_email'])) {
            return;
        }
        
        $subject = '[' . get_bloginfo('name') . '] Security Alert: File Quarantined';
        
        $message = "A potentially malicious file has been quarantined on your WordPress site.\n\n";
        $message .= "File: " . $file_path . "\n";
        $message .= "Reason: " . $reason . "\n";
        $message .= "Time: " . date('Y-m-d H:i:s') . "\n\n";
        $message .= "The file has been safely quarantined and replaced with a harmless placeholder.\n";
        $message .= "Please review the threat in your WordPress AI Security Scanner admin panel.\n\n";
        $message .= "Dashboard: " . admin_url('admin.php?page=wp-ai-security-scanner') . "\n";
        
        wp_mail($settings['notification_email'], $subject, $message);
    }
    
    private function send_cleaning_notification($file_path, $threats_cleaned) {
        $settings = get_option('wp_ai_security_scanner_settings', array());
        
        if (empty($settings['email_notifications']) || empty($settings['notification_email'])) {
            return;
        }
        
        $subject = '[' . get_bloginfo('name') . '] Security Alert: File Cleaned';
        
        $message = "A file has been automatically cleaned of malicious code.\n\n";
        $message .= "File: " . $file_path . "\n";
        $message .= "Threats Removed: " . $threats_cleaned . "\n";
        $message .= "Time: " . date('Y-m-d H:i:s') . "\n\n";
        $message .= "A backup of the original file has been created for your records.\n";
        $message .= "Please review the changes in your WordPress AI Security Scanner admin panel.\n\n";
        $message .= "Dashboard: " . admin_url('admin.php?page=wp-ai-security-scanner') . "\n";
        
        wp_mail($settings['notification_email'], $subject, $message);
    }
    
    private function send_scheduled_scan_notification($scan_result) {
        $settings = get_option('wp_ai_security_scanner_settings', array());
        
        if (empty($settings['email_notifications']) || empty($settings['notification_email'])) {
            return;
        }
        
        $subject = '[' . get_bloginfo('name') . '] Security Alert: Scheduled Scan Results';
        
        $message = "Your scheduled security scan has detected potential threats.\n\n";
        $message .= "Scan Results:\n";
        $message .= "- Total Files Scanned: " . $scan_result['total_files'] . "\n";
        $message .= "- Threats Found: " . $scan_result['threats_found'] . "\n";
        $message .= "- Scan ID: " . $scan_result['scan_id'] . "\n";
        $message .= "- Time: " . date('Y-m-d H:i:s') . "\n\n";
        $message .= "Please review the threats in your WordPress AI Security Scanner admin panel.\n\n";
        $message .= "Dashboard: " . admin_url('admin.php?page=wp-ai-security-scanner') . "\n";
        
        wp_mail($settings['notification_email'], $subject, $message);
    }
    
    public function get_security_recommendations() {
        $recommendations = array();
        
        if (!defined('DISALLOW_FILE_EDIT') || !DISALLOW_FILE_EDIT) {
            $recommendations[] = array(
                'title' => 'Disable File Editing',
                'description' => 'Add define("DISALLOW_FILE_EDIT", true); to wp-config.php to prevent file editing through the admin panel.',
                'severity' => 'high'
            );
        }
        
        if (!defined('WP_DEBUG') || WP_DEBUG) {
            $recommendations[] = array(
                'title' => 'Disable Debug Mode',
                'description' => 'Set WP_DEBUG to false in production environments to prevent information disclosure.',
                'severity' => 'medium'
            );
        }
        
        $wp_version = get_bloginfo('version');
        $latest_version = $this->get_latest_wordpress_version();
        
        if (version_compare($wp_version, $latest_version, '<')) {
            $recommendations[] = array(
                'title' => 'Update WordPress',
                'description' => "WordPress {$latest_version} is available. Current version: {$wp_version}",
                'severity' => 'high'
            );
        }
        
        return $recommendations;
    }
    
    private function get_latest_wordpress_version() {
        $version_check = wp_remote_get('https://api.wordpress.org/core/version-check/1.7/');
        
        if (is_wp_error($version_check)) {
            return get_bloginfo('version');
        }
        
        $version_data = json_decode(wp_remote_retrieve_body($version_check), true);
        
        if (isset($version_data['offers'][0]['version'])) {
            return $version_data['offers'][0]['version'];
        }
        
        return get_bloginfo('version');
    }
    
    public function get_quarantine_directory() {
        return $this->quarantine_dir;
    }
    
    public function get_quarantine_size() {
        $size = 0;
        
        if (!is_dir($this->quarantine_dir)) {
            return $size;
        }
        
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->quarantine_dir)
        );
        
        foreach ($files as $file) {
            if ($file->isFile()) {
                $size += $file->getSize();
            }
        }
        
        return $size;
    }
}