<?php

class WP_AI_Security_Scanner_Scanner_Test extends WP_UnitTestCase {
    
    private $scanner;
    private $test_dir;
    
    public function setUp() {
        parent::setUp();
        
        $this->test_dir = sys_get_temp_dir() . '/ai_scanner_test_' . time();
        mkdir($this->test_dir, 0755, true);
        
        $this->scanner = new WP_AI_Security_Scanner_Scanner();
        
        $database = new WP_AI_Security_Scanner_Database();
        $database->create_tables();
    }
    
    public function tearDown() {
        parent::tearDown();
        
        if (is_dir($this->test_dir)) {
            $this->remove_directory($this->test_dir);
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
    
    public function test_file_integrity_hash() {
        $test_file = $this->test_dir . '/test.php';
        $content = '<?php echo "Hello World"; ?>';
        
        file_put_contents($test_file, $content);
        
        $hash = $this->scanner->get_file_integrity_hash($test_file);
        $expected_hash = hash('sha256', $content);
        
        $this->assertEquals($expected_hash, $hash);
        
        $non_existent_hash = $this->scanner->get_file_integrity_hash('/non/existent/file.php');
        $this->assertFalse($non_existent_hash);
    }
    
    public function test_verify_file_integrity() {
        $test_file = $this->test_dir . '/test.php';
        $content = '<?php echo "Hello World"; ?>';
        
        file_put_contents($test_file, $content);
        
        $hash = hash('sha256', $content);
        
        $this->assertTrue($this->scanner->verify_file_integrity($test_file, $hash));
        
        $wrong_hash = hash('sha256', 'different content');
        $this->assertFalse($this->scanner->verify_file_integrity($test_file, $wrong_hash));
        
        $this->assertFalse($this->scanner->verify_file_integrity('/non/existent/file.php', $hash));
    }
    
    public function test_scan_progress_tracking() {
        $progress = $this->scanner->get_scan_progress();
        
        $this->assertIsArray($progress);
        $this->assertArrayHasKey('total_files', $progress);
        $this->assertArrayHasKey('scanned_files', $progress);
        $this->assertArrayHasKey('threats_found', $progress);
        $this->assertArrayHasKey('status', $progress);
        $this->assertEquals('idle', $progress['status']);
    }
    
    public function test_scan_with_test_files() {
        $clean_file = $this->test_dir . '/clean.php';
        $malicious_file = $this->test_dir . '/malicious.php';
        
        file_put_contents($clean_file, '<?php echo "Clean file"; ?>');
        file_put_contents($malicious_file, '<?php eval(base64_decode($_POST["cmd"])); ?>');
        
        $result = $this->scanner->start_scan(array($this->test_dir));
        
        $this->assertIsArray($result);
        $this->assertArrayHasKey('scan_id', $result);
        $this->assertArrayHasKey('status', $result);
        $this->assertArrayHasKey('threats_found', $result);
        
        $this->assertGreaterThan(0, $result['threats_found']);
        
        $scan_summary = $this->scanner->get_scan_summary($result['scan_id']);
        $this->assertIsArray($scan_summary);
        $this->assertArrayHasKey('total_threats', $scan_summary);
        $this->assertArrayHasKey('critical_threats', $scan_summary);
        $this->assertArrayHasKey('affected_files', $scan_summary);
        
        $this->assertGreaterThan(0, $scan_summary['total_threats']);
        $this->assertContains($malicious_file, $scan_summary['affected_files']);
    }
    
    public function test_scan_file_type_filtering() {
        $php_file = $this->test_dir . '/test.php';
        $js_file = $this->test_dir . '/test.js';
        $txt_file = $this->test_dir . '/test.txt';
        $image_file = $this->test_dir . '/test.jpg';
        
        file_put_contents($php_file, '<?php echo "PHP file"; ?>');
        file_put_contents($js_file, 'console.log("JS file");');
        file_put_contents($txt_file, 'Text file content');
        file_put_contents($image_file, 'fake image content');
        
        update_option('wp_ai_security_scanner_settings', array(
            'file_extensions' => array('php', 'js'),
            'max_file_size' => 10485760,
            'scan_paths' => array($this->test_dir)
        ));
        
        $result = $this->scanner->start_scan(array($this->test_dir));
        
        $this->assertEquals(2, $result['scanned_files']);
    }
    
    public function test_scan_file_size_filtering() {
        $small_file = $this->test_dir . '/small.php';
        $large_file = $this->test_dir . '/large.php';
        
        file_put_contents($small_file, '<?php echo "Small file"; ?>');
        file_put_contents($large_file, str_repeat('A', 1000));
        
        update_option('wp_ai_security_scanner_settings', array(
            'file_extensions' => array('php'),
            'max_file_size' => 500, // 500 bytes
            'scan_paths' => array($this->test_dir)
        ));
        
        $result = $this->scanner->start_scan(array($this->test_dir));
        
        $this->assertEquals(1, $result['scanned_files']);
    }
    
    public function test_scan_directory_exclusion() {
        $regular_dir = $this->test_dir . '/regular';
        $cache_dir = $this->test_dir . '/wp-content/cache';
        
        mkdir($regular_dir, 0755, true);
        mkdir($cache_dir, 0755, true);
        
        file_put_contents($regular_dir . '/file.php', '<?php echo "Regular"; ?>');
        file_put_contents($cache_dir . '/cached.php', '<?php echo "Cached"; ?>');
        
        $result = $this->scanner->start_scan(array($this->test_dir));
        
        $this->assertEquals(1, $result['scanned_files']);
    }
    
    public function test_scan_history() {
        $test_file = $this->test_dir . '/test.php';
        file_put_contents($test_file, '<?php echo "Test"; ?>');
        
        $this->scanner->start_scan(array($this->test_dir));
        
        $history = $this->scanner->get_scan_history(5);
        $this->assertIsArray($history);
        
        if (!empty($history)) {
            $this->assertObjectHasAttribute('scan_id', $history[0]);
            $this->assertObjectHasAttribute('file_path', $history[0]);
            $this->assertObjectHasAttribute('detected_at', $history[0]);
        }
    }
    
    public function test_cancel_scan() {
        $progress = $this->scanner->get_scan_progress();
        $progress['status'] = 'running';
        update_option('wp_ai_security_scanner_scan_progress', $progress);
        
        $result = $this->scanner->cancel_scan();
        $this->assertTrue($result);
        
        $updated_progress = $this->scanner->get_scan_progress();
        $this->assertEquals('cancelled', $updated_progress['status']);
    }
    
    public function test_scan_summary_statistics() {
        $database = new WP_AI_Security_Scanner_Database();
        $scan_id = 'test_scan_123';
        
        $database->save_scan_result($scan_id, '/file1.php', 'hash1', 'malware', 'critical', 'Critical threat', 0.9);
        $database->save_scan_result($scan_id, '/file2.php', 'hash2', 'suspicious', 'high', 'High threat', 0.8);
        $database->save_scan_result($scan_id, '/file3.php', 'hash3', 'malware', 'medium', 'Medium threat', 0.7);
        $database->save_scan_result($scan_id, '/file1.php', 'hash1', 'backdoor', 'critical', 'Backdoor', 0.95);
        
        $summary = $this->scanner->get_scan_summary($scan_id);
        
        $this->assertEquals(4, $summary['total_threats']);
        $this->assertEquals(2, $summary['critical_threats']);
        $this->assertEquals(1, $summary['high_threats']);
        $this->assertEquals(1, $summary['medium_threats']);
        $this->assertEquals(0, $summary['low_threats']);
        
        $this->assertArrayHasKey('malware', $summary['threat_types']);
        $this->assertArrayHasKey('suspicious', $summary['threat_types']);
        $this->assertArrayHasKey('backdoor', $summary['threat_types']);
        
        $this->assertEquals(2, $summary['threat_types']['malware']);
        $this->assertEquals(1, $summary['threat_types']['suspicious']);
        $this->assertEquals(1, $summary['threat_types']['backdoor']);
        
        $this->assertCount(2, $summary['affected_files']);
        $this->assertContains('/file1.php', $summary['affected_files']);
        $this->assertContains('/file2.php', $summary['affected_files']);
    }
}