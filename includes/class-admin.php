<?php

if (!defined('ABSPATH')) {
    exit;
}

class WP_AI_Security_Scanner_Admin {

    private $database;
    private $scanner;
    private $security;

    public function __construct() {
        $this->database = new WP_AI_Security_Scanner_Database();
        $this->scanner = new WP_AI_Security_Scanner_Scanner();
        $this->security = new WP_AI_Security_Scanner_Security_Features();
    }
    
    public function display_dashboard() {
        $stats = $this->database->get_threat_statistics();
        $last_scan = get_option('wp_ai_security_scanner_last_scan', 0);
        $scan_progress = get_option('wp_ai_security_scanner_scan_progress', array());
        
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <div class="ai-scanner-dashboard">
                <div class="dashboard-widgets">
                    <div class="widget security-status">
                        <h3>Security Status</h3>
                        <div class="status-indicator <?php echo $stats['critical_threats'] > 0 ? 'critical' : ($stats['high_threats'] > 0 ? 'warning' : 'safe'); ?>">
                            <?php if ($stats['critical_threats'] > 0): ?>
                                <span class="dashicons dashicons-warning"></span>
                                <strong>Critical Threats Detected</strong>
                            <?php elseif ($stats['high_threats'] > 0): ?>
                                <span class="dashicons dashicons-info"></span>
                                <strong>High Priority Threats</strong>
                            <?php else: ?>
                                <span class="dashicons dashicons-shield"></span>
                                <strong>System Secure</strong>
                            <?php endif; ?>
                        </div>
                    </div>
                    
                    <div class="widget threat-summary">
                        <h3>Threat Summary</h3>
                        <div class="threat-counts">
                            <div class="threat-count critical">
                                <span class="count"><?php echo intval($stats['critical_threats']); ?></span>
                                <span class="label">Critical</span>
                            </div>
                            <div class="threat-count high">
                                <span class="count"><?php echo intval($stats['high_threats']); ?></span>
                                <span class="label">High</span>
                            </div>
                            <div class="threat-count medium">
                                <span class="count"><?php echo intval($stats['medium_threats']); ?></span>
                                <span class="label">Medium</span>
                            </div>
                            <div class="threat-count low">
                                <span class="count"><?php echo intval($stats['low_threats']); ?></span>
                                <span class="label">Low</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="widget scan-control">
                        <h3>Scan Control</h3>
                        <div class="scan-actions">
                            <?php if (isset($scan_progress['status']) && $scan_progress['status'] === 'running'): ?>
                                <div class="scan-progress">
                                    <div class="progress-bar">
                                        <div class="progress-fill" style="width: <?php echo isset($scan_progress['percentage']) ? $scan_progress['percentage'] : 0; ?>%"></div>
                                    </div>
                                    <p>Scanning in progress... <?php echo isset($scan_progress['percentage']) ? round($scan_progress['percentage'], 1) : 0; ?>%</p>
                                    <button type="button" class="button" id="cancel-scan">Cancel Scan</button>
                                </div>
                            <?php else: ?>
                                <button type="button" class="button button-primary" id="start-scan">Start Full Scan</button>
                                <button type="button" class="button" id="quick-scan">Quick Scan</button>
                            <?php endif; ?>
                        </div>
                        
                        <?php if ($last_scan > 0): ?>
                            <p class="last-scan">Last scan: <?php echo human_time_diff($last_scan) . ' ago'; ?></p>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="recent-threats">
                    <h3>Recent Threats</h3>
                    <?php $this->display_recent_threats(); ?>
                </div>
            </div>
        </div>
        <?php
    }
    
    public function display_results() {
        $scan_results = $this->database->get_scan_results();
        
        ?>
        <div class="wrap">
            <h1>Scan Results</h1>
            
            <div class="ai-scanner-results">
                <div class="results-filter">
                    <form method="get">
                        <input type="hidden" name="page" value="wp-ai-security-scanner-results">
                        <select name="severity" onchange="this.form.submit()">
                            <option value="">All Severities</option>
                            <option value="critical" <?php selected(isset($_GET['severity']) ? $_GET['severity'] : '', 'critical'); ?>>Critical</option>
                            <option value="high" <?php selected(isset($_GET['severity']) ? $_GET['severity'] : '', 'high'); ?>>High</option>
                            <option value="medium" <?php selected(isset($_GET['severity']) ? $_GET['severity'] : '', 'medium'); ?>>Medium</option>
                            <option value="low" <?php selected(isset($_GET['severity']) ? $_GET['severity'] : '', 'low'); ?>>Low</option>
                        </select>
                        <select name="status" onchange="this.form.submit()">
                            <option value="">All Statuses</option>
                            <option value="active" <?php selected(isset($_GET['status']) ? $_GET['status'] : '', 'active'); ?>>Active</option>
                            <option value="quarantined" <?php selected(isset($_GET['status']) ? $_GET['status'] : '', 'quarantined'); ?>>Quarantined</option>
                            <option value="cleaned" <?php selected(isset($_GET['status']) ? $_GET['status'] : '', 'cleaned'); ?>>Cleaned</option>
                            <option value="ignored" <?php selected(isset($_GET['status']) ? $_GET['status'] : '', 'ignored'); ?>>Ignored</option>
                        </select>
                    </form>
                </div>
                
                <div class="results-table">
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th>File</th>
                                <th>Threat Type</th>
                                <th>Severity</th>
                                <th>Confidence</th>
                                <th>Status</th>
                                <th>Detected</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($scan_results as $result): ?>
                                <tr>
                                    <td>
                                        <strong><?php echo esc_html(basename($result->file_path)); ?></strong>
                                        <div class="file-path"><?php echo esc_html($result->file_path); ?></div>
                                    </td>
                                    <td>
                                        <span class="threat-type"><?php echo esc_html($result->threat_type); ?></span>
                                        <div class="threat-description"><?php echo esc_html($result->threat_description); ?></div>
                                    </td>
                                    <td>
                                        <span class="severity-badge <?php echo esc_attr($result->threat_severity); ?>">
                                            <?php echo esc_html(ucfirst($result->threat_severity)); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <div class="confidence-meter">
                                            <div class="confidence-bar" style="width: <?php echo ($result->confidence_score * 100); ?>%"></div>
                                            <span class="confidence-text"><?php echo round($result->confidence_score * 100); ?>%</span>
                                        </div>
                                    </td>
                                    <td>
                                        <span class="status-badge <?php echo esc_attr($result->status); ?>">
                                            <?php echo esc_html(ucfirst($result->status)); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <?php echo human_time_diff(strtotime($result->detected_at)) . ' ago'; ?>
                                    </td>
                                    <td>
                                        <div class="action-buttons">
                                            <button type="button" class="button button-small view-details" data-id="<?php echo esc_attr($result->id); ?>">View</button>
                                            <?php if ($result->status === 'active'): ?>
                                                <button type="button" class="button button-small quarantine-file" data-id="<?php echo esc_attr($result->id); ?>">Quarantine</button>
                                                <button type="button" class="button button-small ignore-threat" data-id="<?php echo esc_attr($result->id); ?>">Ignore</button>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <?php
    }
    
    public function display_settings() {
        if (isset($_POST['submit']) && wp_verify_nonce($_POST['ai_scanner_settings_nonce'], 'ai_scanner_settings')) {
            $this->save_settings();
            echo '<div class="notice notice-success"><p>Settings saved successfully!</p></div>';
        }
        
        $settings = get_option('wp_ai_security_scanner_settings', array());
        
        ?>
        <div class="wrap">
            <h1>Scanner Settings</h1>
            
            <form method="post" action="">
                <?php wp_nonce_field('ai_scanner_settings', 'ai_scanner_settings_nonce'); ?>
                
                <table class="form-table">
                    <tr>
                        <th scope="row">Scan Paths</th>
                        <td>
                            <textarea name="scan_paths" rows="5" cols="50" class="large-text"><?php 
                                echo esc_textarea(isset($settings['scan_paths']) ? implode("\n", $settings['scan_paths']) : ABSPATH); 
                            ?></textarea>
                            <p class="description">Enter one path per line. Default is WordPress root directory.</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">File Extensions</th>
                        <td>
                            <input type="text" name="file_extensions" value="<?php 
                                echo esc_attr(isset($settings['file_extensions']) ? implode(', ', $settings['file_extensions']) : 'php, js, html, htm, css'); 
                            ?>" class="regular-text">
                            <p class="description">Comma-separated list of file extensions to scan.</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">Max File Size</th>
                        <td>
                            <input type="number" name="max_file_size" value="<?php 
                                echo esc_attr(isset($settings['max_file_size']) ? $settings['max_file_size'] : 10485760); 
                            ?>" class="regular-text">
                            <p class="description">Maximum file size to scan in bytes (default: 10MB).</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">Email Notifications</th>
                        <td>
                            <label>
                                <input type="checkbox" name="email_notifications" value="1" <?php 
                                    checked(isset($settings['email_notifications']) ? $settings['email_notifications'] : true); 
                                ?>>
                                Send email notifications when threats are detected
                            </label>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">Notification Email</th>
                        <td>
                            <input type="email" name="notification_email" value="<?php 
                                echo esc_attr(isset($settings['notification_email']) ? $settings['notification_email'] : get_option('admin_email')); 
                            ?>" class="regular-text">
                            <p class="description">Email address to receive threat notifications.</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">Scan Frequency</th>
                        <td>
                            <select name="scan_frequency">
                                <option value="hourly" <?php selected(isset($settings['scan_frequency']) ? $settings['scan_frequency'] : 'daily', 'hourly'); ?>>Hourly</option>
                                <option value="daily" <?php selected(isset($settings['scan_frequency']) ? $settings['scan_frequency'] : 'daily', 'daily'); ?>>Daily</option>
                                <option value="weekly" <?php selected(isset($settings['scan_frequency']) ? $settings['scan_frequency'] : 'daily', 'weekly'); ?>>Weekly</option>
                                <option value="monthly" <?php selected(isset($settings['scan_frequency']) ? $settings['scan_frequency'] : 'daily', 'monthly'); ?>>Monthly</option>
                            </select>
                            <p class="description">How often to automatically scan for threats.</p>
                        </td>
                    </tr>
                </table>
                
                <h2>AI-Powered Detection</h2>
                <table class="form-table">
                    <tr>
                        <th scope="row">OpenAI Integration</th>
                        <td>
                            <label>
                                <input type="checkbox" name="use_openai" value="1" <?php 
                                    checked(isset($settings['use_openai']) ? $settings['use_openai'] : false); 
                                ?>>
                                Enable OpenAI-powered malware detection
                            </label>
                            <p class="description">Uses GPT-4 to analyze suspicious code patterns. Requires OpenAI API key.</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">OpenAI API Key</th>
                        <td>
                            <input type="password" name="openai_api_key" value="<?php 
                                echo esc_attr(isset($settings['openai_api_key']) ? $settings['openai_api_key'] : ''); 
                            ?>" class="regular-text" placeholder="sk-...">
                            <p class="description">Get your API key from <a href="https://platform.openai.com/api-keys" target="_blank">OpenAI Platform</a>. Keep this secure!</p>
                            <?php if (isset($settings['openai_api_key']) && !empty($settings['openai_api_key'])): ?>
                                <button type="button" class="button" id="test-openai-key">Test API Key</button>
                                <span id="openai-test-result"></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">VirusTotal Integration</th>
                        <td>
                            <label>
                                <input type="checkbox" name="use_virustotal" value="1" <?php 
                                    checked(isset($settings['use_virustotal']) ? $settings['use_virustotal'] : false); 
                                ?>>
                                Enable VirusTotal malware database lookup
                            </label>
                            <p class="description">Cross-references file hashes with VirusTotal's malware database. Requires VirusTotal API key.</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">VirusTotal API Key</th>
                        <td>
                            <input type="password" name="virustotal_api_key" value="<?php 
                                echo esc_attr(isset($settings['virustotal_api_key']) ? $settings['virustotal_api_key'] : ''); 
                            ?>" class="regular-text" placeholder="your_api_key_here">
                            <p class="description">Get your API key from <a href="https://www.virustotal.com/gui/join-us" target="_blank">VirusTotal</a>. Free tier includes 1000 requests/day.</p>
                            <?php if (isset($settings['virustotal_api_key']) && !empty($settings['virustotal_api_key'])): ?>
                                <button type="button" class="button" id="test-virustotal-key">Test API Key</button>
                                <span id="virustotal-test-result"></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">API Usage Limits</th>
                        <td>
                            <p class="description">
                                <strong>OpenAI:</strong> Pay-per-use. GPT-4 Turbo costs ~$0.01-0.03 per file analyzed.<br>
                                <strong>VirusTotal:</strong> Free tier: 1000 requests/day. Paid plans available for higher limits.<br>
                                <em>API calls are only made for files that trigger local heuristic detection.</em>
                            </p>
                        </td>
                    </tr>
                </table>
                
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
    
    private function save_settings() {
        $old_settings = get_option('wp_ai_security_scanner_settings', array());

        // Get API keys from POST - if empty and we have existing encrypted keys, keep them
        $openai_key = sanitize_text_field($_POST['openai_api_key']);
        $virustotal_key = sanitize_text_field($_POST['virustotal_api_key']);

        // Track API key changes for audit logging
        $openai_changed = false;
        $virustotal_changed = false;

        // Handle OpenAI API key - encrypt if provided, keep existing if empty
        if (!empty($openai_key)) {
            // Check if the key is different from the existing one
            $existing_openai = isset($old_settings['openai_api_key']) ? $this->security->decrypt($old_settings['openai_api_key']) : '';
            if ($openai_key !== $existing_openai) {
                $openai_key = $this->security->encrypt($openai_key);
                $openai_changed = true;
            } else {
                $openai_key = $old_settings['openai_api_key'];
            }
        } elseif (isset($old_settings['openai_api_key'])) {
            // Keep existing encrypted key if no new key provided
            $openai_key = $old_settings['openai_api_key'];
        }

        // Handle VirusTotal API key - encrypt if provided, keep existing if empty
        if (!empty($virustotal_key)) {
            // Check if the key is different from the existing one
            $existing_vt = isset($old_settings['virustotal_api_key']) ? $this->security->decrypt($old_settings['virustotal_api_key']) : '';
            if ($virustotal_key !== $existing_vt) {
                $virustotal_key = $this->security->encrypt($virustotal_key);
                $virustotal_changed = true;
            } else {
                $virustotal_key = $old_settings['virustotal_api_key'];
            }
        } elseif (isset($old_settings['virustotal_api_key'])) {
            // Keep existing encrypted key if no new key provided
            $virustotal_key = $old_settings['virustotal_api_key'];
        }

        $settings = array(
            'scan_paths' => array_filter(array_map('trim', explode("\n", $_POST['scan_paths']))),
            'file_extensions' => array_filter(array_map('trim', explode(',', $_POST['file_extensions']))),
            'max_file_size' => intval($_POST['max_file_size']),
            'email_notifications' => isset($_POST['email_notifications']),
            'notification_email' => sanitize_email($_POST['notification_email']),
            'scan_frequency' => sanitize_text_field($_POST['scan_frequency']),
            'use_openai' => isset($_POST['use_openai']),
            'openai_api_key' => $openai_key,
            'use_virustotal' => isset($_POST['use_virustotal']),
            'virustotal_api_key' => $virustotal_key
        );

        update_option('wp_ai_security_scanner_settings', $settings);

        // Log settings change
        $this->security->log_settings_changed($settings);

        // Log API key changes
        if ($openai_changed) {
            $this->security->log_api_key_changed('OpenAI', !empty($openai_key));
        }
        if ($virustotal_changed) {
            $this->security->log_api_key_changed('VirusTotal', !empty($virustotal_key));
        }

        wp_clear_scheduled_hook('wp_ai_security_scanner_cron');
        wp_schedule_event(time(), $settings['scan_frequency'], 'wp_ai_security_scanner_cron');
    }
    
    private function display_recent_threats() {
        $recent_threats = $this->database->get_scan_results(null, 5);
        
        if (empty($recent_threats)) {
            echo '<p>No threats detected in recent scans.</p>';
            return;
        }
        
        echo '<div class="recent-threats-list">';
        foreach ($recent_threats as $threat) {
            ?>
            <div class="threat-item">
                <div class="threat-info">
                    <strong><?php echo esc_html(basename($threat->file_path)); ?></strong>
                    <span class="severity-badge <?php echo esc_attr($threat->threat_severity); ?>">
                        <?php echo esc_html(ucfirst($threat->threat_severity)); ?>
                    </span>
                </div>
                <div class="threat-description">
                    <?php echo esc_html($threat->threat_description); ?>
                </div>
                <div class="threat-meta">
                    Detected <?php echo human_time_diff(strtotime($threat->detected_at)); ?> ago
                </div>
            </div>
            <?php
        }
        echo '</div>';
    }
}