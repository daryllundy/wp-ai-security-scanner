<?php

if (!defined('ABSPATH')) {
    exit;
}

class WP_AI_Security_Scanner_Database {
    
    private $wpdb;
    
    public function __construct() {
        global $wpdb;
        $this->wpdb = $wpdb;
    }
    
    public function create_tables() {
        $charset_collate = $this->wpdb->get_charset_collate();
        
        $sql_results = "CREATE TABLE IF NOT EXISTS {$this->wpdb->prefix}ai_scanner_results (
            id int(11) NOT NULL AUTO_INCREMENT,
            scan_id varchar(32) NOT NULL,
            file_path text NOT NULL,
            file_hash varchar(64) NOT NULL,
            threat_type varchar(50) NOT NULL,
            threat_severity enum('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'medium',
            threat_description text NOT NULL,
            confidence_score decimal(3,2) NOT NULL DEFAULT 0.00,
            status enum('active', 'quarantined', 'cleaned', 'ignored') NOT NULL DEFAULT 'active',
            detected_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY scan_id (scan_id),
            KEY file_hash (file_hash),
            KEY threat_type (threat_type),
            KEY status (status)
        ) $charset_collate;";
        
        $sql_config = "CREATE TABLE IF NOT EXISTS {$this->wpdb->prefix}ai_scanner_config (
            id int(11) NOT NULL AUTO_INCREMENT,
            config_key varchar(100) NOT NULL,
            config_value longtext NOT NULL,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY config_key (config_key)
        ) $charset_collate;";
        
        $sql_quarantine = "CREATE TABLE IF NOT EXISTS {$this->wpdb->prefix}ai_scanner_quarantine (
            id int(11) NOT NULL AUTO_INCREMENT,
            file_path text NOT NULL,
            original_content longtext NOT NULL,
            backup_path text NOT NULL,
            quarantine_reason text NOT NULL,
            quarantined_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            restored_at datetime NULL,
            PRIMARY KEY (id),
            KEY quarantined_at (quarantined_at)
        ) $charset_collate;";

        $sql_audit_log = "CREATE TABLE IF NOT EXISTS {$this->wpdb->prefix}ai_scanner_audit_log (
            id int(11) NOT NULL AUTO_INCREMENT,
            event_type varchar(50) NOT NULL,
            description text NOT NULL,
            severity enum('info', 'warning', 'error', 'critical') NOT NULL DEFAULT 'info',
            user_id bigint(20) unsigned DEFAULT NULL,
            user_ip varchar(45) DEFAULT NULL,
            metadata longtext DEFAULT NULL,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY event_type (event_type),
            KEY severity (severity),
            KEY user_id (user_id),
            KEY created_at (created_at)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');

        dbDelta($sql_results);
        dbDelta($sql_config);
        dbDelta($sql_quarantine);
        dbDelta($sql_audit_log);

        $this->insert_default_config();
    }
    
    private function insert_default_config() {
        $malware_signatures = array(
            'eval_obfuscation' => array(
                'pattern' => '/eval\s*\(\s*base64_decode\s*\(/',
                'description' => 'Obfuscated eval with base64 decode',
                'severity' => 'high'
            ),
            'file_inclusion' => array(
                'pattern' => '/include\s*\(\s*\$_[GET|POST|REQUEST]/',
                'description' => 'Dynamic file inclusion vulnerability',
                'severity' => 'critical'
            ),
            'shell_exec' => array(
                'pattern' => '/shell_exec\s*\(\s*\$_[GET|POST|REQUEST]/',
                'description' => 'Shell command execution from user input',
                'severity' => 'critical'
            ),
            'backdoor_pattern' => array(
                'pattern' => '/c99|r57|wso|b374k|FilesMan|WSO/i',
                'description' => 'Common backdoor shell names',
                'severity' => 'critical'
            ),
            'base64_suspicious' => array(
                'pattern' => '/base64_decode\s*\(\s*[\'"][A-Za-z0-9+\/=]{100,}[\'"]/',
                'description' => 'Suspicious base64 encoded content',
                'severity' => 'medium'
            ),
            'crypto_mining' => array(
                'pattern' => '/coinhive|cryptonight|monero|stratum\+tcp/i',
                'description' => 'Cryptocurrency mining code',
                'severity' => 'high'
            ),
            'sql_injection' => array(
                'pattern' => '/union\s+select.*from.*information_schema/i',
                'description' => 'SQL injection attempt',
                'severity' => 'high'
            ),
            'wordpress_exploit' => array(
                'pattern' => '/wp_users.*password.*md5|wp_options.*siteurl.*update/i',
                'description' => 'WordPress database manipulation',
                'severity' => 'critical'
            )
        );
        
        $this->save_config('malware_signatures', $malware_signatures);
        $this->save_config('last_signature_update', time());
    }
    
    public function save_config($key, $value) {
        $serialized_value = maybe_serialize($value);
        
        $result = $this->wpdb->replace(
            $this->wpdb->prefix . 'ai_scanner_config',
            array(
                'config_key' => $key,
                'config_value' => $serialized_value
            ),
            array('%s', '%s')
        );
        
        return $result !== false;
    }
    
    public function get_config($key, $default = null) {
        $result = $this->wpdb->get_var(
            $this->wpdb->prepare(
                "SELECT config_value FROM {$this->wpdb->prefix}ai_scanner_config WHERE config_key = %s",
                $key
            )
        );
        
        if ($result === null) {
            return $default;
        }
        
        return maybe_unserialize($result);
    }
    
    public function save_scan_result($scan_id, $file_path, $file_hash, $threat_type, $threat_severity, $threat_description, $confidence_score = 0.0) {
        $result = $this->wpdb->insert(
            $this->wpdb->prefix . 'ai_scanner_results',
            array(
                'scan_id' => $scan_id,
                'file_path' => $file_path,
                'file_hash' => $file_hash,
                'threat_type' => $threat_type,
                'threat_severity' => $threat_severity,
                'threat_description' => $threat_description,
                'confidence_score' => $confidence_score,
                'status' => 'active'
            ),
            array('%s', '%s', '%s', '%s', '%s', '%s', '%f', '%s')
        );
        
        return $result !== false;
    }
    
    public function get_scan_results($scan_id = null, $limit = 100) {
        $sql = "SELECT * FROM {$this->wpdb->prefix}ai_scanner_results";
        $params = array();
        
        if ($scan_id) {
            $sql .= " WHERE scan_id = %s";
            $params[] = $scan_id;
        }
        
        $sql .= " ORDER BY detected_at DESC LIMIT %d";
        $params[] = $limit;
        
        if (!empty($params)) {
            $sql = $this->wpdb->prepare($sql, $params);
        }
        
        return $this->wpdb->get_results($sql);
    }
    
    public function get_threat_statistics() {
        $stats = array();
        
        $stats['total_threats'] = $this->wpdb->get_var(
            "SELECT COUNT(*) FROM {$this->wpdb->prefix}ai_scanner_results WHERE status = 'active'"
        );
        
        $stats['critical_threats'] = $this->wpdb->get_var(
            "SELECT COUNT(*) FROM {$this->wpdb->prefix}ai_scanner_results WHERE threat_severity = 'critical' AND status = 'active'"
        );
        
        $stats['high_threats'] = $this->wpdb->get_var(
            "SELECT COUNT(*) FROM {$this->wpdb->prefix}ai_scanner_results WHERE threat_severity = 'high' AND status = 'active'"
        );
        
        $stats['medium_threats'] = $this->wpdb->get_var(
            "SELECT COUNT(*) FROM {$this->wpdb->prefix}ai_scanner_results WHERE threat_severity = 'medium' AND status = 'active'"
        );
        
        $stats['low_threats'] = $this->wpdb->get_var(
            "SELECT COUNT(*) FROM {$this->wpdb->prefix}ai_scanner_results WHERE threat_severity = 'low' AND status = 'active'"
        );
        
        $stats['recent_scans'] = $this->wpdb->get_var(
            "SELECT COUNT(DISTINCT scan_id) FROM {$this->wpdb->prefix}ai_scanner_results WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
        );
        
        return $stats;
    }
    
    public function quarantine_file($file_path, $original_content, $backup_path, $reason) {
        $result = $this->wpdb->insert(
            $this->wpdb->prefix . 'ai_scanner_quarantine',
            array(
                'file_path' => $file_path,
                'original_content' => $original_content,
                'backup_path' => $backup_path,
                'quarantine_reason' => $reason
            ),
            array('%s', '%s', '%s', '%s')
        );
        
        return $result !== false;
    }
    
    public function get_quarantined_files() {
        return $this->wpdb->get_results(
            "SELECT * FROM {$this->wpdb->prefix}ai_scanner_quarantine WHERE restored_at IS NULL ORDER BY quarantined_at DESC"
        );
    }
    
    public function update_threat_status($id, $status) {
        $result = $this->wpdb->update(
            $this->wpdb->prefix . 'ai_scanner_results',
            array('status' => $status),
            array('id' => $id),
            array('%s'),
            array('%d')
        );
        
        return $result !== false;
    }
}