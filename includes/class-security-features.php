<?php

if (!defined('ABSPATH')) {
    exit;
}

class WP_AI_Security_Scanner_Security_Features {

    private $database;
    private $quarantine_dir;

    /**
     * Encryption cipher method
     */
    const CIPHER_METHOD = 'aes-256-cbc';

    /**
     * Rate limit settings for external APIs
     */
    const RATE_LIMIT_OPENAI_PER_MINUTE = 20;
    const RATE_LIMIT_VIRUSTOTAL_PER_MINUTE = 4;
    const RATE_LIMIT_WINDOW = 60; // seconds

    public function __construct() {
        $this->database = new WP_AI_Security_Scanner_Database();
        $this->quarantine_dir = WP_CONTENT_DIR . '/ai-scanner-quarantine/';

        $this->init_hooks();
        $this->ensure_quarantine_dir();
    }

    // ========================================
    // ENCRYPTION METHODS (AES-256)
    // ========================================

    /**
     * Get or generate the encryption key
     *
     * @return string The encryption key
     */
    private function get_encryption_key() {
        $key = get_option('wp_ai_scanner_encryption_key');

        if (empty($key)) {
            // Generate a secure random key
            $key = base64_encode(openssl_random_pseudo_bytes(32));
            update_option('wp_ai_scanner_encryption_key', $key);
        }

        return base64_decode($key);
    }

    /**
     * Encrypt sensitive data using AES-256-CBC
     *
     * @param string $data The data to encrypt
     * @return string|false The encrypted data (base64 encoded) or false on failure
     */
    public function encrypt($data) {
        if (empty($data)) {
            return $data;
        }

        if (!function_exists('openssl_encrypt')) {
            error_log('WP AI Scanner: OpenSSL extension not available for encryption');
            return $data;
        }

        $key = $this->get_encryption_key();
        $iv_length = openssl_cipher_iv_length(self::CIPHER_METHOD);
        $iv = openssl_random_pseudo_bytes($iv_length);

        $encrypted = openssl_encrypt($data, self::CIPHER_METHOD, $key, OPENSSL_RAW_DATA, $iv);

        if ($encrypted === false) {
            error_log('WP AI Scanner: Encryption failed');
            return false;
        }

        // Combine IV and encrypted data, then base64 encode
        $result = base64_encode($iv . $encrypted);

        // Add a prefix to identify encrypted values
        return 'enc:' . $result;
    }

    /**
     * Decrypt sensitive data encrypted with AES-256-CBC
     *
     * @param string $encrypted_data The encrypted data (base64 encoded with 'enc:' prefix)
     * @return string|false The decrypted data or false on failure
     */
    public function decrypt($encrypted_data) {
        if (empty($encrypted_data)) {
            return $encrypted_data;
        }

        // Check if data is encrypted (has our prefix)
        if (strpos($encrypted_data, 'enc:') !== 0) {
            // Data is not encrypted, return as-is (backward compatibility)
            return $encrypted_data;
        }

        if (!function_exists('openssl_decrypt')) {
            error_log('WP AI Scanner: OpenSSL extension not available for decryption');
            return false;
        }

        // Remove the prefix
        $encrypted_data = substr($encrypted_data, 4);

        $key = $this->get_encryption_key();
        $data = base64_decode($encrypted_data);

        if ($data === false) {
            error_log('WP AI Scanner: Base64 decode failed during decryption');
            return false;
        }

        $iv_length = openssl_cipher_iv_length(self::CIPHER_METHOD);
        $iv = substr($data, 0, $iv_length);
        $encrypted = substr($data, $iv_length);

        $decrypted = openssl_decrypt($encrypted, self::CIPHER_METHOD, $key, OPENSSL_RAW_DATA, $iv);

        if ($decrypted === false) {
            error_log('WP AI Scanner: Decryption failed');
            return false;
        }

        return $decrypted;
    }

    /**
     * Check if a value is encrypted
     *
     * @param string $value The value to check
     * @return bool True if encrypted, false otherwise
     */
    public function is_encrypted($value) {
        return is_string($value) && strpos($value, 'enc:') === 0;
    }

    // ========================================
    // RATE LIMITING METHODS
    // ========================================

    /**
     * Check if an API call is allowed based on rate limits
     *
     * @param string $api_name The API name ('openai' or 'virustotal')
     * @return bool True if allowed, false if rate limited
     */
    public function check_rate_limit($api_name) {
        $limit = $this->get_rate_limit($api_name);
        $transient_key = 'wp_ai_scanner_rate_' . $api_name;

        $calls = get_transient($transient_key);

        if ($calls === false) {
            $calls = array();
        }

        // Remove calls outside the time window
        $current_time = time();
        $calls = array_filter($calls, function($timestamp) use ($current_time) {
            return ($current_time - $timestamp) < self::RATE_LIMIT_WINDOW;
        });

        // Check if we're at the limit
        if (count($calls) >= $limit) {
            $this->log_audit_event('rate_limit_exceeded', "Rate limit exceeded for {$api_name} API", 'warning');
            return false;
        }

        return true;
    }

    /**
     * Record an API call for rate limiting
     *
     * @param string $api_name The API name ('openai' or 'virustotal')
     */
    public function record_api_call($api_name) {
        $transient_key = 'wp_ai_scanner_rate_' . $api_name;

        $calls = get_transient($transient_key);

        if ($calls === false) {
            $calls = array();
        }

        // Add current timestamp
        $calls[] = time();

        // Store with expiration matching the rate limit window
        set_transient($transient_key, $calls, self::RATE_LIMIT_WINDOW);
    }

    /**
     * Get the rate limit for a specific API
     *
     * @param string $api_name The API name
     * @return int The rate limit per minute
     */
    public function get_rate_limit($api_name) {
        switch ($api_name) {
            case 'openai':
                return self::RATE_LIMIT_OPENAI_PER_MINUTE;
            case 'virustotal':
                return self::RATE_LIMIT_VIRUSTOTAL_PER_MINUTE;
            default:
                return 10; // Default rate limit
        }
    }

    /**
     * Get remaining API calls for rate limiting
     *
     * @param string $api_name The API name
     * @return int Number of remaining calls allowed
     */
    public function get_remaining_api_calls($api_name) {
        $limit = $this->get_rate_limit($api_name);
        $transient_key = 'wp_ai_scanner_rate_' . $api_name;

        $calls = get_transient($transient_key);

        if ($calls === false) {
            return $limit;
        }

        // Remove calls outside the time window
        $current_time = time();
        $calls = array_filter($calls, function($timestamp) use ($current_time) {
            return ($current_time - $timestamp) < self::RATE_LIMIT_WINDOW;
        });

        return max(0, $limit - count($calls));
    }

    /**
     * Get seconds until rate limit resets
     *
     * @param string $api_name The API name
     * @return int Seconds until reset, 0 if not rate limited
     */
    public function get_rate_limit_reset_time($api_name) {
        $transient_key = 'wp_ai_scanner_rate_' . $api_name;

        $calls = get_transient($transient_key);

        if ($calls === false || empty($calls)) {
            return 0;
        }

        $oldest_call = min($calls);
        $reset_time = ($oldest_call + self::RATE_LIMIT_WINDOW) - time();

        return max(0, $reset_time);
    }

    // ========================================
    // AUDIT LOGGING METHODS
    // ========================================

    /**
     * Log a security audit event
     *
     * @param string $event_type The type of event
     * @param string $description Description of the event
     * @param string $severity The severity level (info, warning, error, critical)
     * @param array $metadata Additional metadata for the event
     * @return bool True on success, false on failure
     */
    public function log_audit_event($event_type, $description, $severity = 'info', $metadata = array()) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'ai_scanner_audit_log';

        // Get current user info
        $user_id = get_current_user_id();
        $user_ip = $this->get_client_ip();

        // Sanitize metadata
        $metadata_json = !empty($metadata) ? wp_json_encode($metadata) : null;

        $result = $wpdb->insert(
            $table_name,
            array(
                'event_type' => sanitize_text_field($event_type),
                'description' => sanitize_text_field($description),
                'severity' => sanitize_text_field($severity),
                'user_id' => $user_id,
                'user_ip' => sanitize_text_field($user_ip),
                'metadata' => $metadata_json,
                'created_at' => current_time('mysql')
            ),
            array('%s', '%s', '%s', '%d', '%s', '%s', '%s')
        );

        return $result !== false;
    }

    /**
     * Get audit log entries
     *
     * @param array $args Query arguments
     * @return array Array of audit log entries
     */
    public function get_audit_log($args = array()) {
        global $wpdb;

        $defaults = array(
            'limit' => 100,
            'offset' => 0,
            'event_type' => null,
            'severity' => null,
            'user_id' => null,
            'date_from' => null,
            'date_to' => null,
            'order' => 'DESC'
        );

        $args = wp_parse_args($args, $defaults);
        $table_name = $wpdb->prefix . 'ai_scanner_audit_log';

        $sql = "SELECT * FROM {$table_name} WHERE 1=1";
        $params = array();

        if (!empty($args['event_type'])) {
            $sql .= " AND event_type = %s";
            $params[] = $args['event_type'];
        }

        if (!empty($args['severity'])) {
            $sql .= " AND severity = %s";
            $params[] = $args['severity'];
        }

        if (!empty($args['user_id'])) {
            $sql .= " AND user_id = %d";
            $params[] = $args['user_id'];
        }

        if (!empty($args['date_from'])) {
            $sql .= " AND created_at >= %s";
            $params[] = $args['date_from'];
        }

        if (!empty($args['date_to'])) {
            $sql .= " AND created_at <= %s";
            $params[] = $args['date_to'];
        }

        $order = strtoupper($args['order']) === 'ASC' ? 'ASC' : 'DESC';
        $sql .= " ORDER BY created_at {$order}";
        $sql .= " LIMIT %d OFFSET %d";
        $params[] = $args['limit'];
        $params[] = $args['offset'];

        if (!empty($params)) {
            $sql = $wpdb->prepare($sql, $params);
        }

        return $wpdb->get_results($sql);
    }

    /**
     * Get audit log statistics
     *
     * @return array Statistics about audit log entries
     */
    public function get_audit_statistics() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'ai_scanner_audit_log';

        $stats = array();

        // Total events
        $stats['total_events'] = $wpdb->get_var("SELECT COUNT(*) FROM {$table_name}");

        // Events by severity
        $stats['by_severity'] = $wpdb->get_results(
            "SELECT severity, COUNT(*) as count FROM {$table_name} GROUP BY severity",
            OBJECT_K
        );

        // Events in last 24 hours
        $stats['last_24h'] = $wpdb->get_var(
            "SELECT COUNT(*) FROM {$table_name} WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        );

        // Events in last 7 days
        $stats['last_7d'] = $wpdb->get_var(
            "SELECT COUNT(*) FROM {$table_name} WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
        );

        // Most common event types
        $stats['common_events'] = $wpdb->get_results(
            "SELECT event_type, COUNT(*) as count FROM {$table_name} GROUP BY event_type ORDER BY count DESC LIMIT 10"
        );

        return $stats;
    }

    /**
     * Clean up old audit log entries
     *
     * @param int $days_to_keep Number of days to keep logs (default 90)
     * @return int Number of entries deleted
     */
    public function cleanup_audit_log($days_to_keep = 90) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'ai_scanner_audit_log';

        $result = $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table_name} WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $days_to_keep
        ));

        if ($result > 0) {
            $this->log_audit_event('audit_cleanup', "Cleaned up {$result} old audit log entries", 'info');
        }

        return $result;
    }

    /**
     * Get the client IP address
     *
     * @return string The client IP address
     */
    private function get_client_ip() {
        $ip = '';

        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // Can contain multiple IPs, get the first one
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($ips[0]);
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }

        // Validate IP
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }

        return 'unknown';
    }

    // ========================================
    // PREDEFINED AUDIT EVENT HELPERS
    // ========================================

    /**
     * Log a scan started event
     *
     * @param string $scan_id The scan ID
     * @param string $scan_type The type of scan (full, quick)
     */
    public function log_scan_started($scan_id, $scan_type = 'full') {
        $this->log_audit_event('scan_started', "Security scan started (ID: {$scan_id})", 'info', array(
            'scan_id' => $scan_id,
            'scan_type' => $scan_type
        ));
    }

    /**
     * Log a scan completed event
     *
     * @param string $scan_id The scan ID
     * @param int $files_scanned Number of files scanned
     * @param int $threats_found Number of threats found
     */
    public function log_scan_completed($scan_id, $files_scanned, $threats_found) {
        $severity = $threats_found > 0 ? 'warning' : 'info';
        $this->log_audit_event('scan_completed', "Security scan completed (ID: {$scan_id})", $severity, array(
            'scan_id' => $scan_id,
            'files_scanned' => $files_scanned,
            'threats_found' => $threats_found
        ));
    }

    /**
     * Log a threat detected event
     *
     * @param string $file_path The file path
     * @param string $threat_type The type of threat
     * @param string $threat_severity The severity of the threat
     */
    public function log_threat_detected($file_path, $threat_type, $threat_severity) {
        $severity = in_array($threat_severity, array('critical', 'high')) ? 'critical' : 'warning';
        $this->log_audit_event('threat_detected', "Threat detected: {$threat_type} in {$file_path}", $severity, array(
            'file_path' => $file_path,
            'threat_type' => $threat_type,
            'threat_severity' => $threat_severity
        ));
    }

    /**
     * Log a file quarantined event
     *
     * @param string $file_path The file path
     * @param string $reason The reason for quarantine
     */
    public function log_file_quarantined($file_path, $reason) {
        $this->log_audit_event('file_quarantined', "File quarantined: {$file_path}", 'warning', array(
            'file_path' => $file_path,
            'reason' => $reason
        ));
    }

    /**
     * Log a file restored event
     *
     * @param string $file_path The file path
     */
    public function log_file_restored($file_path) {
        $this->log_audit_event('file_restored', "File restored from quarantine: {$file_path}", 'info', array(
            'file_path' => $file_path
        ));
    }

    /**
     * Log a settings changed event
     *
     * @param array $changed_settings The settings that were changed
     */
    public function log_settings_changed($changed_settings) {
        $this->log_audit_event('settings_changed', 'Security scanner settings updated', 'info', array(
            'changed_fields' => array_keys($changed_settings)
        ));
    }

    /**
     * Log an API key update event
     *
     * @param string $api_name The API name
     * @param bool $was_added Whether the key was added (true) or removed (false)
     */
    public function log_api_key_changed($api_name, $was_added) {
        $action = $was_added ? 'configured' : 'removed';
        $this->log_audit_event('api_key_changed', "{$api_name} API key {$action}", 'info', array(
            'api_name' => $api_name,
            'action' => $action
        ));
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