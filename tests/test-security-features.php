<?php

class WP_AI_Security_Scanner_Security_Features_Test extends WP_UnitTestCase {
    
    private $security_features;
    private $test_dir;
    
    public function setUp() {
        parent::setUp();
        
        $this->test_dir = sys_get_temp_dir() . '/ai_scanner_security_test_' . time();
        mkdir($this->test_dir, 0755, true);
        
        $database = new WP_AI_Security_Scanner_Database();
        $database->create_tables();
        
        $this->security_features = new WP_AI_Security_Scanner_Security_Features();
    }
    
    public function tearDown() {
        parent::tearDown();
        
        if (is_dir($this->test_dir)) {
            $this->remove_directory($this->test_dir);
        }
        
        $quarantine_dir = WP_CONTENT_DIR . '/ai-scanner-quarantine/';
        if (is_dir($quarantine_dir)) {
            $this->remove_directory($quarantine_dir);
        }
        
        global $wpdb;
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}ai_scanner_results");
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}ai_scanner_config");
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}ai_scanner_quarantine");
    }
    
    private function remove_directory($dir) {
        if (!is_dir($dir)) {
            return;
        }
        
        $files = array_diff(scandir($dir), array('.', '..'));
        
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            if (is_dir($path)) {
                $this->remove_directory($path);
            } else {
                unlink($path);
            }
        }
        
        rmdir($dir);
    }
    
    public function test_quarantine_file_success() {
        $test_file = $this->test_dir . '/malicious.php';
        $malicious_content = '<?php eval($_POST["cmd"]); ?>';
        
        file_put_contents($test_file, $malicious_content);
        
        $result = $this->security_features->quarantine_file($test_file, 'Test quarantine');
        
        $this->assertTrue($result);
        
        $quarantine_dir = $this->security_features->get_quarantine_directory();
        $this->assertTrue(is_dir($quarantine_dir));
        
        $replacement_content = file_get_contents($test_file);
        $this->assertStringContainsString('QUARANTINED FILE', $replacement_content);
        $this->assertStringContainsString('CodeGuard AI Security Scanner', $replacement_content);
        
        $quarantine_files = scandir($quarantine_dir);
        $backup_files = array_filter($quarantine_files, function($file) {
            return strpos($file, 'malicious.php') !== false && $file !== '.' && $file !== '..';
        });
        
        $this->assertCount(1, $backup_files);
        
        $backup_file = $quarantine_dir . reset($backup_files);
        $backup_content = file_get_contents($backup_file);
        $this->assertEquals($malicious_content, $backup_content);
    }
    
    public function test_quarantine_file_not_found() {
        $non_existent_file = $this->test_dir . '/non_existent.php';
        
        $result = $this->security_features->quarantine_file($non_existent_file, 'Test');
        
        $this->assertInstanceOf('WP_Error', $result);
        $this->assertEquals('file_not_found', $result->get_error_code());
    }
    
    public function test_restore_quarantined_file() {
        $test_file = $this->test_dir . '/restore_test.php';
        $original_content = '<?php echo "Original content"; ?>';
        
        file_put_contents($test_file, $original_content);
        
        $this->security_features->quarantine_file($test_file, 'Test quarantine');
        
        $quarantined_content = file_get_contents($test_file);
        $this->assertStringContainsString('QUARANTINED FILE', $quarantined_content);
        
        $result = $this->security_features->restore_file($test_file);
        
        $this->assertTrue($result);
        
        $restored_content = file_get_contents($test_file);
        $this->assertEquals($original_content, $restored_content);
    }
    
    public function test_restore_non_quarantined_file() {
        $test_file = $this->test_dir . '/normal.php';
        file_put_contents($test_file, '<?php echo "Normal file"; ?>');
        
        $result = $this->security_features->restore_file($test_file);
        
        $this->assertInstanceOf('WP_Error', $result);
        $this->assertEquals('file_not_quarantined', $result->get_error_code());
    }
    
    public function test_clean_file_with_patterns() {
        $test_file = $this->test_dir . '/infected.php';
        $infected_content = '<?php 
            echo "Clean content";
            eval($_POST["malicious"]);
            echo "More clean content";
        ?>';
        
        file_put_contents($test_file, $infected_content);
        
        $threat_patterns = array(
            '/eval\s*\([^)]*\);?/'
        );
        
        $result = $this->security_features->clean_file($test_file, $threat_patterns);
        
        $this->assertTrue($result);
        
        $cleaned_content = file_get_contents($test_file);
        $this->assertStringNotContainsString('eval', $cleaned_content);
        $this->assertStringContainsString('Clean content', $cleaned_content);
        $this->assertStringContainsString('More clean content', $cleaned_content);
    }
    
    public function test_clean_file_no_threats() {
        $test_file = $this->test_dir . '/clean.php';
        $clean_content = '<?php echo "Clean file"; ?>';
        
        file_put_contents($test_file, $clean_content);
        
        $threat_patterns = array(
            '/eval\s*\([^)]*\);?/'
        );
        
        $result = $this->security_features->clean_file($test_file, $threat_patterns);
        
        $this->assertInstanceOf('WP_Error', $result);
        $this->assertEquals('no_changes', $result->get_error_code());
    }
    
    public function test_get_security_recommendations() {
        $recommendations = $this->security_features->get_security_recommendations();
        
        $this->assertIsArray($recommendations);
        $this->assertNotEmpty($recommendations);
        
        foreach ($recommendations as $recommendation) {
            $this->assertArrayHasKey('title', $recommendation);
            $this->assertArrayHasKey('description', $recommendation);
            $this->assertArrayHasKey('severity', $recommendation);
            $this->assertContains($recommendation['severity'], array('low', 'medium', 'high', 'critical'));
        }
    }
    
    public function test_quarantine_directory_creation() {
        $quarantine_dir = $this->security_features->get_quarantine_directory();
        
        $this->assertTrue(is_dir($quarantine_dir));
        $this->assertTrue(file_exists($quarantine_dir . '.htaccess'));
        $this->assertTrue(file_exists($quarantine_dir . 'index.php'));
        
        $htaccess_content = file_get_contents($quarantine_dir . '.htaccess');
        $this->assertStringContainsString('Deny from all', $htaccess_content);
        
        $index_content = file_get_contents($quarantine_dir . 'index.php');
        $this->assertStringContainsString('Silence is golden', $index_content);
    }
    
    public function test_quarantine_size_calculation() {
        $test_file = $this->test_dir . '/size_test.php';
        $content = str_repeat('A', 1000);
        
        file_put_contents($test_file, $content);
        
        $initial_size = $this->security_features->get_quarantine_size();
        
        $this->security_features->quarantine_file($test_file, 'Size test');
        
        $final_size = $this->security_features->get_quarantine_size();
        
        $this->assertGreaterThan($initial_size, $final_size);
        $this->assertGreaterThanOrEqual(1000, $final_size - $initial_size);
    }
    
    public function test_ajax_quarantine_file() {
        $database = new WP_AI_Security_Scanner_Database();
        
        $test_file = $this->test_dir . '/ajax_test.php';
        file_put_contents($test_file, '<?php eval($_POST["cmd"]); ?>');
        
        $database->save_scan_result('test_scan', $test_file, 'hash123', 'malware', 'high', 'Test malware', 0.9);
        
        $results = $database->get_scan_results('test_scan');
        $threat_id = $results[0]->id;
        
        $_POST['threat_id'] = $threat_id;
        $_POST['nonce'] = wp_create_nonce('wp_ai_scanner_nonce');
        
        $user_id = $this->factory->user->create(array('role' => 'administrator'));
        wp_set_current_user($user_id);
        
        ob_start();
        try {
            $this->security_features->ajax_quarantine_file();
        } catch (WPAjaxDieStopException $e) {
            // Expected for wp_send_json_success
        }
        $output = ob_get_clean();
        
        $response = json_decode($output, true);
        $this->assertTrue($response['success']);
        
        $updated_results = $database->get_scan_results('test_scan');
        $this->assertEquals('quarantined', $updated_results[0]->status);
    }
    
    public function test_ajax_ignore_threat() {
        $database = new WP_AI_Security_Scanner_Database();
        
        $database->save_scan_result('test_scan', '/test.php', 'hash123', 'suspicious', 'low', 'Test threat', 0.6);
        
        $results = $database->get_scan_results('test_scan');
        $threat_id = $results[0]->id;
        
        $_POST['threat_id'] = $threat_id;
        $_POST['nonce'] = wp_create_nonce('wp_ai_scanner_nonce');
        
        $user_id = $this->factory->user->create(array('role' => 'administrator'));
        wp_set_current_user($user_id);
        
        ob_start();
        try {
            $this->security_features->ajax_ignore_threat();
        } catch (WPAjaxDieStopException $e) {
            // Expected for wp_send_json_success
        }
        $output = ob_get_clean();
        
        $response = json_decode($output, true);
        $this->assertTrue($response['success']);
        
        $updated_results = $database->get_scan_results('test_scan');
        $this->assertEquals('ignored', $updated_results[0]->status);
    }
    
    public function test_ajax_get_threat_stats() {
        $database = new WP_AI_Security_Scanner_Database();
        
        $database->save_scan_result('test_scan', '/file1.php', 'hash1', 'malware', 'critical', 'Critical threat', 0.9);
        $database->save_scan_result('test_scan', '/file2.php', 'hash2', 'suspicious', 'high', 'High threat', 0.8);
        $database->save_scan_result('test_scan', '/file3.php', 'hash3', 'malware', 'medium', 'Medium threat', 0.7);
        
        $_POST['nonce'] = wp_create_nonce('wp_ai_scanner_nonce');
        
        $user_id = $this->factory->user->create(array('role' => 'administrator'));
        wp_set_current_user($user_id);
        
        ob_start();
        try {
            $this->security_features->ajax_get_threat_stats();
        } catch (WPAjaxDieStopException $e) {
            // Expected for wp_send_json_success
        }
        $output = ob_get_clean();
        
        $response = json_decode($output, true);
        $this->assertTrue($response['success']);
        
        $stats = $response['data'];
        $this->assertEquals(3, $stats['total_threats']);
        $this->assertEquals(1, $stats['critical_threats']);
        $this->assertEquals(1, $stats['high_threats']);
        $this->assertEquals(1, $stats['medium_threats']);
    }
    
    public function test_scheduled_scan() {
        $test_file = $this->test_dir . '/scheduled_test.php';
        file_put_contents($test_file, '<?php eval($_POST["cmd"]); ?>');
        
        update_option('wp_ai_security_scanner_settings', array(
            'scan_paths' => array($this->test_dir),
            'file_extensions' => array('php'),
            'max_file_size' => 10485760,
            'email_notifications' => false
        ));
        
        $this->security_features->scheduled_scan();
        
        $database = new WP_AI_Security_Scanner_Database();
        $results = $database->get_scan_results();
        
        $this->assertNotEmpty($results);
        $this->assertGreaterThan(0, count($results));
    }
}