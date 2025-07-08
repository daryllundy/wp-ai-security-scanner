<?php

class WP_AI_Security_Scanner_Enhanced_Scanner_Test extends WP_UnitTestCase {
    
    private $scanner;
    private $database;
    
    public function setUp() {
        parent::setUp();
        
        $this->database = new WP_AI_Security_Scanner_Database();
        $this->database->create_tables();
        
        $this->scanner = new WP_AI_Security_Scanner_Scanner();
    }
    
    public function tearDown() {
        parent::tearDown();
        
        global $wpdb;
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}ai_scanner_results");
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}ai_scanner_config");
        $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}ai_scanner_quarantine");
    }
    
    public function test_enhanced_detection_pipeline() {
        // Test full detection pipeline with multiple threat types
        $test_files = [
            'eval_threat.php' => '<?php eval(base64_decode($_POST["cmd"])); ?>',
            'shell_threat.php' => '<?php shell_exec($_GET["command"]); ?>',
            'inclusion_threat.php' => '<?php include($_REQUEST["file"]); ?>',
            'mining_threat.php' => '<?php $coinhive = "mining script"; ?>',
            'clean_file.php' => '<?php echo "Hello World"; ?>'
        ];
        
        $temp_dir = wp_tempnam();
        unlink($temp_dir);
        mkdir($temp_dir);
        
        foreach ($test_files as $filename => $content) {
            file_put_contents($temp_dir . '/' . $filename, $content);
        }
        
        $result = $this->scanner->start_scan([$temp_dir]);
        
        $this->assertEquals('completed', $result['status']);
        $this->assertGreaterThan(0, $result['threats_found']);
        
        // Clean up
        array_map('unlink', glob($temp_dir . '/*'));
        rmdir($temp_dir);
    }
    
    public function test_quick_scan_vs_full_scan() {
        // Test that quick scan targets specific directories
        $temp_dir = wp_tempnam();
        unlink($temp_dir);
        mkdir($temp_dir);
        
        // Create test file
        file_put_contents($temp_dir . '/threat.php', '<?php eval($_POST["malware"]); ?>');
        
        // Mock quick scan paths
        $quick_scan_paths = [$temp_dir];
        
        $quick_result = $this->scanner->start_scan($quick_scan_paths);
        $full_result = $this->scanner->start_scan();
        
        // Quick scan should complete faster (less files)
        $this->assertLessThanOrEqual($full_result['total_files'], $quick_result['total_files']);
        
        // Clean up
        unlink($temp_dir . '/threat.php');
        rmdir($temp_dir);
    }
    
    public function test_scan_progress_tracking() {
        $scan_id = uniqid('test_', true);
        
        // Start a scan and check progress
        $result = $this->scanner->start_scan();
        
        $progress = $this->scanner->get_scan_progress();
        
        $this->assertArrayHasKey('percentage', $progress);
        $this->assertArrayHasKey('total_files', $progress);
        $this->assertArrayHasKey('scanned_files', $progress);
        $this->assertArrayHasKey('threats_found', $progress);
        $this->assertArrayHasKey('status', $progress);
        
        $this->assertGreaterThanOrEqual(0, $progress['percentage']);
        $this->assertLessThanOrEqual(100, $progress['percentage']);
    }
    
    public function test_scan_timeout_handling() {
        // Test that scans don't run indefinitely
        $large_file_content = str_repeat('<?php echo "test"; ?>', 10000);
        
        $temp_dir = wp_tempnam();
        unlink($temp_dir);
        mkdir($temp_dir);
        
        // Create many test files
        for ($i = 0; $i < 50; $i++) {
            file_put_contents($temp_dir . "/file{$i}.php", $large_file_content);
        }
        
        $start_time = time();
        $result = $this->scanner->start_scan([$temp_dir]);
        $end_time = time();
        
        // Should complete within reasonable time (5 minutes max in our implementation)
        $this->assertLessThan(310, $end_time - $start_time);
        
        // Clean up
        array_map('unlink', glob($temp_dir . '/*'));
        rmdir($temp_dir);
    }
    
    public function test_file_exclusion_rules() {
        $temp_dir = wp_tempnam();
        unlink($temp_dir);
        mkdir($temp_dir);
        mkdir($temp_dir . '/wp-content');
        mkdir($temp_dir . '/wp-content/cache');
        
        // Create files in excluded directory
        file_put_contents($temp_dir . '/wp-content/cache/threat.php', '<?php eval($_POST["cmd"]); ?>');
        file_put_contents($temp_dir . '/allowed.php', '<?php eval($_POST["cmd"]); ?>');
        
        $result = $this->scanner->start_scan([$temp_dir]);
        
        // Should find threat in allowed location but not in cache
        $scan_results = $this->database->get_scan_results();
        
        $found_in_cache = false;
        $found_in_allowed = false;
        
        foreach ($scan_results as $threat) {
            if (strpos($threat->file_path, 'cache') !== false) {
                $found_in_cache = true;
            }
            if (strpos($threat->file_path, 'allowed.php') !== false) {
                $found_in_allowed = true;
            }
        }
        
        $this->assertFalse($found_in_cache);
        $this->assertTrue($found_in_allowed);
        
        // Clean up
        unlink($temp_dir . '/wp-content/cache/threat.php');
        unlink($temp_dir . '/allowed.php');
        rmdir($temp_dir . '/wp-content/cache');
        rmdir($temp_dir . '/wp-content');
        rmdir($temp_dir);
    }
    
    public function test_file_size_limits() {
        // Test that files exceeding size limits are skipped
        $temp_dir = wp_tempnam();
        unlink($temp_dir);
        mkdir($temp_dir);
        
        // Create a large file that exceeds default 10MB limit
        $large_content = str_repeat('A', 11 * 1024 * 1024); // 11MB
        file_put_contents($temp_dir . '/large_file.php', $large_content);
        
        // Create a normal sized file
        file_put_contents($temp_dir . '/normal_file.php', '<?php eval($_POST["cmd"]); ?>');
        
        $result = $this->scanner->start_scan([$temp_dir]);
        
        // Should scan normal file but skip large file
        $scan_results = $this->database->get_scan_results();
        
        $found_large = false;
        $found_normal = false;
        
        foreach ($scan_results as $threat) {
            if (strpos($threat->file_path, 'large_file.php') !== false) {
                $found_large = true;
            }
            if (strpos($threat->file_path, 'normal_file.php') !== false) {
                $found_normal = true;
            }
        }
        
        $this->assertFalse($found_large);
        $this->assertTrue($found_normal);
        
        // Clean up
        unlink($temp_dir . '/large_file.php');
        unlink($temp_dir . '/normal_file.php');
        rmdir($temp_dir);
    }
    
    public function test_scan_cancellation() {
        // Start a scan
        $result = $this->scanner->start_scan();
        
        // Cancel it
        $cancel_result = $this->scanner->cancel_scan();
        
        $this->assertTrue($cancel_result);
        
        // Check that status is updated
        $progress = $this->scanner->get_scan_progress();
        $this->assertEquals('cancelled', $progress['status']);
    }
    
    public function test_scan_summary_generation() {
        // Create test files with different threat types
        $temp_dir = wp_tempnam();
        unlink($temp_dir);
        mkdir($temp_dir);
        
        $test_files = [
            'critical.php' => '<?php eval(base64_decode($_POST["backdoor"])); ?>',
            'high.php' => '<?php shell_exec($_GET["cmd"]); ?>',
            'medium.php' => '<?php echo $_POST["data"]; ?>',
        ];
        
        foreach ($test_files as $filename => $content) {
            file_put_contents($temp_dir . '/' . $filename, $content);
        }
        
        $result = $this->scanner->start_scan([$temp_dir]);
        $summary = $this->scanner->get_scan_summary($result['scan_id']);
        
        $this->assertArrayHasKey('scan_id', $summary);
        $this->assertArrayHasKey('total_threats', $summary);
        $this->assertArrayHasKey('critical_threats', $summary);
        $this->assertArrayHasKey('high_threats', $summary);
        $this->assertArrayHasKey('medium_threats', $summary);
        $this->assertArrayHasKey('low_threats', $summary);
        $this->assertArrayHasKey('threat_types', $summary);
        $this->assertArrayHasKey('affected_files', $summary);
        
        $this->assertGreaterThan(0, $summary['total_threats']);
        
        // Clean up
        array_map('unlink', glob($temp_dir . '/*'));
        rmdir($temp_dir);
    }
    
    public function test_file_integrity_hash() {
        $test_content = '<?php echo "test content"; ?>';
        $temp_file = wp_tempnam();
        file_put_contents($temp_file, $test_content);
        
        $hash1 = $this->scanner->get_file_integrity_hash($temp_file);
        $hash2 = $this->scanner->get_file_integrity_hash($temp_file);
        
        // Same file should produce same hash
        $this->assertEquals($hash1, $hash2);
        
        // Modify file
        file_put_contents($temp_file, $test_content . ' modified');
        $hash3 = $this->scanner->get_file_integrity_hash($temp_file);
        
        // Modified file should have different hash
        $this->assertNotEquals($hash1, $hash3);
        
        unlink($temp_file);
    }
    
    public function test_file_integrity_verification() {
        $test_content = '<?php echo "test content"; ?>';
        $temp_file = wp_tempnam();
        file_put_contents($temp_file, $test_content);
        
        $original_hash = $this->scanner->get_file_integrity_hash($temp_file);
        
        // Verify unchanged file
        $is_intact = $this->scanner->verify_file_integrity($temp_file, $original_hash);
        $this->assertTrue($is_intact);
        
        // Modify file
        file_put_contents($temp_file, $test_content . ' modified');
        
        // Verify changed file
        $is_intact = $this->scanner->verify_file_integrity($temp_file, $original_hash);
        $this->assertFalse($is_intact);
        
        unlink($temp_file);
    }
    
    public function test_scan_history_tracking() {
        // Run multiple scans
        $result1 = $this->scanner->start_scan();
        $result2 = $this->scanner->start_scan();
        
        $history = $this->scanner->get_scan_history(5);
        
        $this->assertGreaterThanOrEqual(2, count($history));
        
        // Check that results are ordered by date (newest first)
        if (count($history) >= 2) {
            $time1 = strtotime($history[0]->detected_at);
            $time2 = strtotime($history[1]->detected_at);
            $this->assertGreaterThanOrEqual($time2, $time1);
        }
    }
    
    public function test_concurrent_scan_prevention() {
        // Start first scan
        $result1 = $this->scanner->start_scan();
        
        // Try to start second scan while first is running
        update_option('wp_ai_security_scanner_scan_progress', [
            'status' => 'running',
            'start_time' => time()
        ]);
        
        $result2 = $this->scanner->start_scan();
        
        // Second scan should handle concurrent execution gracefully
        $this->assertArrayHasKey('status', $result2);
    }
}