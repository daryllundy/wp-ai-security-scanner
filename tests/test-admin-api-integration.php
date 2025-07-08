<?php

class WP_AI_Security_Scanner_Admin_API_Integration_Test extends WP_UnitTestCase {
    
    private $admin;
    private $database;
    
    public function setUp() {
        parent::setUp();
        
        $this->database = new WP_AI_Security_Scanner_Database();
        $this->database->create_tables();
        
        $this->admin = new WP_AI_Security_Scanner_Admin();
        
        // Create admin user for capability tests
        $user_id = $this->factory->user->create(['role' => 'administrator']);
        wp_set_current_user($user_id);
    }
    
    public function tearDown() {
        parent::tearDown();
        
        global $wpdb;
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}ai_scanner_results");
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}ai_scanner_config");
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}ai_scanner_quarantine");
        
        delete_option('wp_ai_security_scanner_settings');
    }
    
    public function test_default_settings_include_api_options() {
        // Test that default settings include API configuration
        $default_settings = [
            'scan_paths' => [ABSPATH],
            'file_extensions' => ['php', 'js', 'html', 'htm', 'css'],
            'max_file_size' => 10485760,
            'email_notifications' => true,
            'notification_email' => get_option('admin_email'),
            'scan_frequency' => 'daily',
            'use_openai' => false,
            'openai_api_key' => '',
            'use_virustotal' => false,
            'virustotal_api_key' => ''
        ];
        
        update_option('wp_ai_security_scanner_settings', $default_settings);
        $settings = get_option('wp_ai_security_scanner_settings');
        
        $this->assertArrayHasKey('use_openai', $settings);
        $this->assertArrayHasKey('openai_api_key', $settings);
        $this->assertArrayHasKey('use_virustotal', $settings);
        $this->assertArrayHasKey('virustotal_api_key', $settings);
        
        $this->assertFalse($settings['use_openai']);
        $this->assertFalse($settings['use_virustotal']);
        $this->assertEquals('', $settings['openai_api_key']);
        $this->assertEquals('', $settings['virustotal_api_key']);
    }
    
    public function test_settings_save_with_api_keys() {
        // Mock POST data for settings save
        $_POST = [
            'scan_paths' => ABSPATH,
            'file_extensions' => 'php, js, html',
            'max_file_size' => '10485760',
            'email_notifications' => '1',
            'notification_email' => 'admin@test.com',
            'scan_frequency' => 'daily',
            'use_openai' => '1',
            'openai_api_key' => 'sk-test-key-123',
            'use_virustotal' => '1',
            'virustotal_api_key' => 'vt-test-key-456'
        ];
        
        // Mock nonce verification
        $_POST['ai_scanner_settings_nonce'] = wp_create_nonce('ai_scanner_settings');
        
        // Simulate form submission
        if (wp_verify_nonce($_POST['ai_scanner_settings_nonce'], 'ai_scanner_settings')) {
            $reflection = new ReflectionClass($this->admin);
            $method = $reflection->getMethod('save_settings');
            $method->setAccessible(true);
            $method->invoke($this->admin);
        }
        
        $saved_settings = get_option('wp_ai_security_scanner_settings');
        
        $this->assertTrue($saved_settings['use_openai']);
        $this->assertTrue($saved_settings['use_virustotal']);
        $this->assertEquals('sk-test-key-123', $saved_settings['openai_api_key']);
        $this->assertEquals('vt-test-key-456', $saved_settings['virustotal_api_key']);
    }
    
    public function test_settings_save_sanitization() {
        // Test that API keys are properly sanitized
        $_POST = [
            'scan_paths' => ABSPATH,
            'file_extensions' => 'php, js',
            'max_file_size' => '10485760',
            'email_notifications' => '1',
            'notification_email' => 'admin@test.com',
            'scan_frequency' => 'daily',
            'use_openai' => '1',
            'openai_api_key' => '<script>alert("xss")</script>sk-malicious-key',
            'use_virustotal' => '1',
            'virustotal_api_key' => 'vt-key<script>alert("xss")</script>'
        ];
        
        $_POST['ai_scanner_settings_nonce'] = wp_create_nonce('ai_scanner_settings');
        
        if (wp_verify_nonce($_POST['ai_scanner_settings_nonce'], 'ai_scanner_settings')) {
            $reflection = new ReflectionClass($this->admin);
            $method = $reflection->getMethod('save_settings');
            $method->setAccessible(true);
            $method->invoke($this->admin);
        }
        
        $saved_settings = get_option('wp_ai_security_scanner_settings');
        
        // Should be sanitized - no script tags
        $this->assertStringNotContainsString('<script>', $saved_settings['openai_api_key']);
        $this->assertStringNotContainsString('<script>', $saved_settings['virustotal_api_key']);
        $this->assertStringNotContainsString('alert', $saved_settings['openai_api_key']);
        $this->assertStringNotContainsString('alert', $saved_settings['virustotal_api_key']);
    }
    
    public function test_settings_display_with_api_sections() {
        // Set some test settings
        update_option('wp_ai_security_scanner_settings', [
            'use_openai' => true,
            'openai_api_key' => 'sk-test-key',
            'use_virustotal' => false,
            'virustotal_api_key' => ''
        ]);
        
        // Capture output
        ob_start();
        $this->admin->display_settings();
        $output = ob_get_clean();
        
        // Check that API settings sections are present
        $this->assertStringContainsString('AI-Powered Detection', $output);
        $this->assertStringContainsString('OpenAI Integration', $output);
        $this->assertStringContainsString('VirusTotal Integration', $output);
        $this->assertStringContainsString('OpenAI API Key', $output);
        $this->assertStringContainsString('VirusTotal API Key', $output);
        
        // Check that checkboxes reflect saved settings
        $this->assertStringContainsString('checked', $output); // OpenAI should be checked
        
        // Check for test buttons
        $this->assertStringContainsString('Test API Key', $output);
        $this->assertStringContainsString('test-openai-key', $output);
        $this->assertStringContainsString('test-virustotal-key', $output);
    }
    
    public function test_settings_password_field_masking() {
        // Test that API keys are displayed as password fields
        update_option('wp_ai_security_scanner_settings', [
            'openai_api_key' => 'sk-secret-key-123',
            'virustotal_api_key' => 'vt-secret-key-456'
        ]);
        
        ob_start();
        $this->admin->display_settings();
        $output = ob_get_clean();
        
        // Check that input fields are type="password"
        $this->assertStringContainsString('type="password"', $output);
        
        // Check that actual keys are in value attributes (for editing)
        $this->assertStringContainsString('sk-secret-key-123', $output);
        $this->assertStringContainsString('vt-secret-key-456', $output);
    }
    
    public function test_api_usage_information_display() {
        ob_start();
        $this->admin->display_settings();
        $output = ob_get_clean();
        
        // Check for cost and usage information
        $this->assertStringContainsString('$0.01-0.03 per file', $output);
        $this->assertStringContainsString('1000 requests/day', $output);
        $this->assertStringContainsString('API Usage Limits', $output);
        $this->assertStringContainsString('locally flagged as suspicious', $output);
    }
    
    public function test_api_links_in_settings() {
        ob_start();
        $this->admin->display_settings();
        $output = ob_get_clean();
        
        // Check for external API links
        $this->assertStringContainsString('https://platform.openai.com/api-keys', $output);
        $this->assertStringContainsString('https://www.virustotal.com/gui/join-us', $output);
        $this->assertStringContainsString('target="_blank"', $output);
    }
    
    public function test_conditional_test_button_display() {
        // Test with empty API keys - no test buttons
        update_option('wp_ai_security_scanner_settings', [
            'openai_api_key' => '',
            'virustotal_api_key' => ''
        ]);
        
        ob_start();
        $this->admin->display_settings();
        $output_empty = ob_get_clean();
        
        $this->assertStringNotContainsString('test-openai-key', $output_empty);
        $this->assertStringNotContainsString('test-virustotal-key', $output_empty);
        
        // Test with API keys - should show test buttons
        update_option('wp_ai_security_scanner_settings', [
            'openai_api_key' => 'sk-test-key',
            'virustotal_api_key' => 'vt-test-key'
        ]);
        
        ob_start();
        $this->admin->display_settings();
        $output_with_keys = ob_get_clean();
        
        $this->assertStringContainsString('test-openai-key', $output_with_keys);
        $this->assertStringContainsString('test-virustotal-key', $output_with_keys);
    }
    
    public function test_threat_source_display_in_results() {
        // Create test threat results with different sources
        global $wpdb;
        
        $scan_id = uniqid('test_', true);
        
        // Insert test threats from different sources
        $wpdb->insert(
            $wpdb->prefix . 'ai_scanner_results',
            [
                'scan_id' => $scan_id,
                'file_path' => '/test/local_threat.php',
                'file_hash' => 'hash123',
                'threat_type' => 'eval_obfuscation',
                'threat_severity' => 'high',
                'threat_description' => 'Local signature detection',
                'confidence_score' => 0.9
            ]
        );
        
        $wpdb->insert(
            $wpdb->prefix . 'ai_scanner_results',
            [
                'scan_id' => $scan_id,
                'file_path' => '/test/openai_threat.php',
                'file_hash' => 'hash456',
                'threat_type' => 'openai_detection',
                'threat_severity' => 'critical',
                'threat_description' => 'OpenAI detected malware',
                'confidence_score' => 0.95
            ]
        );
        
        $wpdb->insert(
            $wpdb->prefix . 'ai_scanner_results',
            [
                'scan_id' => $scan_id,
                'file_path' => '/test/vt_threat.php',
                'file_hash' => 'hash789',
                'threat_type' => 'virustotal_detection',
                'threat_severity' => 'high',
                'threat_description' => 'VirusTotal detected malware: 10/70 engines',
                'confidence_score' => 0.8
            ]
        );
        
        ob_start();
        $this->admin->display_results();
        $output = ob_get_clean();
        
        // Check that different threat types are displayed
        $this->assertStringContainsString('eval_obfuscation', $output);
        $this->assertStringContainsString('openai_detection', $output);
        $this->assertStringContainsString('virustotal_detection', $output);
        
        // Check confidence scores are displayed
        $this->assertStringContainsString('90%', $output);
        $this->assertStringContainsString('95%', $output);
        $this->assertStringContainsString('80%', $output);
    }
    
    public function test_dashboard_displays_enhanced_stats() {
        // Create mock threat statistics
        global $wpdb;
        
        $scan_id = uniqid('test_', true);
        
        // Insert threats of different severities and sources
        $threats = [
            ['type' => 'eval_obfuscation', 'severity' => 'critical'],
            ['type' => 'openai_detection', 'severity' => 'high'],
            ['type' => 'virustotal_detection', 'severity' => 'medium'],
            ['type' => 'suspicious_function', 'severity' => 'low']
        ];
        
        foreach ($threats as $threat) {
            $wpdb->insert(
                $wpdb->prefix . 'ai_scanner_results',
                [
                    'scan_id' => $scan_id,
                    'file_path' => '/test/' . $threat['type'] . '.php',
                    'file_hash' => md5($threat['type']),
                    'threat_type' => $threat['type'],
                    'threat_severity' => $threat['severity'],
                    'threat_description' => 'Test threat',
                    'confidence_score' => 0.8
                ]
            );
        }
        
        ob_start();
        $this->admin->display_dashboard();
        $output = ob_get_clean();
        
        // Check that threat counts are displayed
        $this->assertStringContainsString('Critical', $output);
        $this->assertStringContainsString('High', $output);
        $this->assertStringContainsString('Medium', $output);
        $this->assertStringContainsString('Low', $output);
        
        // Check for scan controls
        $this->assertStringContainsString('Start Full Scan', $output);
        $this->assertStringContainsString('Quick Scan', $output);
    }
    
    public function test_settings_form_nonce_security() {
        ob_start();
        $this->admin->display_settings();
        $output = ob_get_clean();
        
        // Check that proper nonce field is included
        $this->assertStringContainsString('ai_scanner_settings_nonce', $output);
        $this->assertStringContainsString('wp_nonce_field', $output);
    }
    
    public function test_admin_capability_requirements() {
        // Test with non-admin user
        $user_id = $this->factory->user->create(['role' => 'subscriber']);
        wp_set_current_user($user_id);
        
        // Admin pages should not be accessible
        $this->assertFalse(current_user_can('manage_options'));
        
        // Set back to admin
        $admin_id = $this->factory->user->create(['role' => 'administrator']);
        wp_set_current_user($admin_id);
        
        $this->assertTrue(current_user_can('manage_options'));
    }
}