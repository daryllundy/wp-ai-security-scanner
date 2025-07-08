<?php

class WP_AI_Security_Scanner_Database_Test extends WP_UnitTestCase {
    
    private $database;
    
    public function setUp() {
        parent::setUp();
        $this->database = new WP_AI_Security_Scanner_Database();
    }
    
    public function tearDown() {
        parent::tearDown();
        
        global $wpdb;
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}ai_scanner_results");
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}ai_scanner_config");
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}ai_scanner_quarantine");
    }
    
    public function test_create_tables() {
        $this->database->create_tables();
        
        global $wpdb;
        
        $results_table = $wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}ai_scanner_results'");
        $config_table = $wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}ai_scanner_config'");
        $quarantine_table = $wpdb->get_var("SHOW TABLES LIKE '{$wpdb->prefix}ai_scanner_quarantine'");
        
        $this->assertEquals($wpdb->prefix . 'ai_scanner_results', $results_table);
        $this->assertEquals($wpdb->prefix . 'ai_scanner_config', $config_table);
        $this->assertEquals($wpdb->prefix . 'ai_scanner_quarantine', $quarantine_table);
    }
    
    public function test_save_and_get_config() {
        $this->database->create_tables();
        
        $test_data = array(
            'test_key' => 'test_value',
            'array_data' => array('item1', 'item2', 'item3')
        );
        
        $result = $this->database->save_config('test_config', $test_data);
        $this->assertTrue($result);
        
        $retrieved_data = $this->database->get_config('test_config');
        $this->assertEquals($test_data, $retrieved_data);
        
        $non_existent = $this->database->get_config('non_existent', 'default_value');
        $this->assertEquals('default_value', $non_existent);
    }
    
    public function test_save_scan_result() {
        $this->database->create_tables();
        
        $scan_id = 'test_scan_123';
        $file_path = '/test/file.php';
        $file_hash = 'abc123def456';
        $threat_type = 'malware';
        $threat_severity = 'high';
        $threat_description = 'Test malware detected';
        $confidence_score = 0.95;
        
        $result = $this->database->save_scan_result(
            $scan_id,
            $file_path,
            $file_hash,
            $threat_type,
            $threat_severity,
            $threat_description,
            $confidence_score
        );
        
        $this->assertTrue($result);
        
        $saved_results = $this->database->get_scan_results($scan_id);
        $this->assertCount(1, $saved_results);
        
        $saved_result = $saved_results[0];
        $this->assertEquals($scan_id, $saved_result->scan_id);
        $this->assertEquals($file_path, $saved_result->file_path);
        $this->assertEquals($file_hash, $saved_result->file_hash);
        $this->assertEquals($threat_type, $saved_result->threat_type);
        $this->assertEquals($threat_severity, $saved_result->threat_severity);
        $this->assertEquals($threat_description, $saved_result->threat_description);
        $this->assertEquals($confidence_score, $saved_result->confidence_score);
    }
    
    public function test_get_threat_statistics() {
        $this->database->create_tables();
        
        $this->database->save_scan_result('scan1', '/file1.php', 'hash1', 'malware', 'critical', 'Critical threat', 0.9);
        $this->database->save_scan_result('scan1', '/file2.php', 'hash2', 'malware', 'high', 'High threat', 0.8);
        $this->database->save_scan_result('scan1', '/file3.php', 'hash3', 'suspicious', 'medium', 'Medium threat', 0.7);
        $this->database->save_scan_result('scan1', '/file4.php', 'hash4', 'suspicious', 'low', 'Low threat', 0.6);
        
        $stats = $this->database->get_threat_statistics();
        
        $this->assertEquals(4, $stats['total_threats']);
        $this->assertEquals(1, $stats['critical_threats']);
        $this->assertEquals(1, $stats['high_threats']);
        $this->assertEquals(1, $stats['medium_threats']);
        $this->assertEquals(1, $stats['low_threats']);
    }
    
    public function test_quarantine_file() {
        $this->database->create_tables();
        
        $file_path = '/test/malicious.php';
        $original_content = '<?php eval($_POST["cmd"]); ?>';
        $backup_path = '/quarantine/backup_malicious.php';
        $reason = 'Malicious eval detected';
        
        $result = $this->database->quarantine_file($file_path, $original_content, $backup_path, $reason);
        $this->assertTrue($result);
        
        $quarantined_files = $this->database->get_quarantined_files();
        $this->assertCount(1, $quarantined_files);
        
        $quarantined_file = $quarantined_files[0];
        $this->assertEquals($file_path, $quarantined_file->file_path);
        $this->assertEquals($original_content, $quarantined_file->original_content);
        $this->assertEquals($backup_path, $quarantined_file->backup_path);
        $this->assertEquals($reason, $quarantined_file->quarantine_reason);
    }
    
    public function test_update_threat_status() {
        $this->database->create_tables();
        
        $this->database->save_scan_result('scan1', '/file1.php', 'hash1', 'malware', 'high', 'Test threat', 0.9);
        
        $results = $this->database->get_scan_results('scan1');
        $threat_id = $results[0]->id;
        
        $result = $this->database->update_threat_status($threat_id, 'quarantined');
        $this->assertTrue($result);
        
        $updated_results = $this->database->get_scan_results('scan1');
        $this->assertEquals('quarantined', $updated_results[0]->status);
    }
    
    public function test_malware_signatures_initialization() {
        $this->database->create_tables();
        
        $signatures = $this->database->get_config('malware_signatures', array());
        
        $this->assertIsArray($signatures);
        $this->assertNotEmpty($signatures);
        $this->assertArrayHasKey('eval_obfuscation', $signatures);
        $this->assertArrayHasKey('file_inclusion', $signatures);
        $this->assertArrayHasKey('shell_exec', $signatures);
        
        $eval_signature = $signatures['eval_obfuscation'];
        $this->assertArrayHasKey('pattern', $eval_signature);
        $this->assertArrayHasKey('description', $eval_signature);
        $this->assertArrayHasKey('severity', $eval_signature);
    }
}