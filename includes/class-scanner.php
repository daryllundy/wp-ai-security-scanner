<?php

if (!defined('ABSPATH')) {
    exit;
}

class WP_AI_Security_Scanner_Scanner {
    
    private $database;
    private $malware_detector;
    private $scan_id;
    private $progress;
    
    public function __construct() {
        $this->database = new WP_AI_Security_Scanner_Database();
        $this->malware_detector = new WP_AI_Security_Scanner_Malware_Detector();
        $this->scan_id = null;
        $this->progress = array(
            'total_files' => 0,
            'scanned_files' => 0,
            'threats_found' => 0,
            'current_file' => '',
            'status' => 'idle',
            'start_time' => 0,
            'end_time' => 0
        );
    }
    
    public function start_scan($scan_paths = null) {
        $this->scan_id = uniqid('scan_', true);
        $this->progress['status'] = 'running';
        $this->progress['start_time'] = time();
        $this->progress['scanned_files'] = 0;
        $this->progress['threats_found'] = 0;
        
        if ($scan_paths === null) {
            $settings = get_option('wp_ai_security_scanner_settings', array());
            $scan_paths = isset($settings['scan_paths']) ? $settings['scan_paths'] : array(ABSPATH);
        }
        
        update_option('wp_ai_security_scanner_scan_progress', $this->progress);
        
        try {
            $files = $this->collect_files($scan_paths);
            $this->progress['total_files'] = count($files);
            update_option('wp_ai_security_scanner_scan_progress', $this->progress);
            
            foreach ($files as $file) {
                $this->scan_file($file);
                $this->progress['scanned_files']++;
                $this->progress['current_file'] = $file;
                
                if ($this->progress['scanned_files'] % 10 === 0) {
                    update_option('wp_ai_security_scanner_scan_progress', $this->progress);
                }
                
                if (time() - $this->progress['start_time'] > 300) {
                    break;
                }
            }
            
            $this->progress['status'] = 'completed';
            $this->progress['end_time'] = time();
            
        } catch (Exception $e) {
            $this->progress['status'] = 'error';
            $this->progress['error_message'] = $e->getMessage();
            error_log('WP AI Security Scanner Error: ' . $e->getMessage());
        }
        
        update_option('wp_ai_security_scanner_scan_progress', $this->progress);
        update_option('wp_ai_security_scanner_last_scan', time());
        
        return array(
            'scan_id' => $this->scan_id,
            'status' => $this->progress['status'],
            'total_files' => $this->progress['total_files'],
            'scanned_files' => $this->progress['scanned_files'],
            'threats_found' => $this->progress['threats_found']
        );
    }
    
    private function collect_files($scan_paths) {
        $files = array();
        $settings = get_option('wp_ai_security_scanner_settings', array());
        $allowed_extensions = isset($settings['file_extensions']) ? $settings['file_extensions'] : array('php', 'js', 'html', 'htm', 'css');
        $max_file_size = isset($settings['max_file_size']) ? $settings['max_file_size'] : 10485760; // 10MB
        
        $excluded_dirs = array(
            'wp-content/cache',
            'wp-content/backup',
            'wp-content/uploads',
            'wp-admin/includes',
            'wp-includes',
            '.git',
            'node_modules',
            'vendor'
        );
        
        foreach ($scan_paths as $path) {
            $files = array_merge($files, $this->scan_directory($path, $allowed_extensions, $max_file_size, $excluded_dirs));
        }
        
        return array_unique($files);
    }
    
    private function scan_directory($directory, $allowed_extensions, $max_file_size, $excluded_dirs, $depth = 0) {
        $files = array();
        
        if ($depth > 10) {
            return $files;
        }
        
        if (!is_dir($directory)) {
            return $files;
        }
        
        foreach ($excluded_dirs as $excluded) {
            if (strpos($directory, $excluded) !== false) {
                return $files;
            }
        }
        
        try {
            $iterator = new DirectoryIterator($directory);
            
            foreach ($iterator as $file) {
                if ($file->isDot()) {
                    continue;
                }
                
                $file_path = $file->getPathname();
                
                if ($file->isDir()) {
                    $files = array_merge($files, $this->scan_directory($file_path, $allowed_extensions, $max_file_size, $excluded_dirs, $depth + 1));
                } elseif ($file->isFile()) {
                    if ($file->getSize() > $max_file_size) {
                        continue;
                    }
                    
                    $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
                    
                    if (in_array($extension, $allowed_extensions)) {
                        $files[] = $file_path;
                    }
                }
            }
            
        } catch (Exception $e) {
            error_log('WP AI Security Scanner: Error scanning directory ' . $directory . ': ' . $e->getMessage());
        }
        
        return $files;
    }
    
    private function scan_file($file_path) {
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return;
        }
        
        try {
            $file_content = file_get_contents($file_path);
            
            if ($file_content === false) {
                return;
            }
            
            $file_hash = hash('sha256', $file_content);
            
            $threats = $this->malware_detector->analyze_file($file_path, $file_content);
            
            foreach ($threats as $threat) {
                $this->database->save_scan_result(
                    $this->scan_id,
                    $file_path,
                    $file_hash,
                    $threat['type'],
                    $threat['severity'],
                    $threat['description'],
                    $threat['confidence']
                );
                
                $this->progress['threats_found']++;
            }
            
        } catch (Exception $e) {
            error_log('WP AI Security Scanner: Error scanning file ' . $file_path . ': ' . $e->getMessage());
        }
    }
    
    public function get_scan_progress() {
        $progress = get_option('wp_ai_security_scanner_scan_progress', $this->progress);
        
        if ($progress['total_files'] > 0) {
            $progress['percentage'] = round(($progress['scanned_files'] / $progress['total_files']) * 100, 2);
        } else {
            $progress['percentage'] = 0;
        }
        
        if ($progress['start_time'] > 0) {
            $progress['elapsed_time'] = time() - $progress['start_time'];
            
            if ($progress['scanned_files'] > 0) {
                $progress['estimated_time'] = round(($progress['elapsed_time'] / $progress['scanned_files']) * ($progress['total_files'] - $progress['scanned_files']));
            } else {
                $progress['estimated_time'] = 0;
            }
        }
        
        return $progress;
    }
    
    public function cancel_scan() {
        $progress = get_option('wp_ai_security_scanner_scan_progress', $this->progress);
        $progress['status'] = 'cancelled';
        $progress['end_time'] = time();
        
        update_option('wp_ai_security_scanner_scan_progress', $progress);
        
        return true;
    }
    
    public function get_scan_history($limit = 10) {
        return $this->database->get_scan_results(null, $limit);
    }
    
    public function get_file_integrity_hash($file_path) {
        if (!file_exists($file_path)) {
            return false;
        }
        
        $content = file_get_contents($file_path);
        if ($content === false) {
            return false;
        }
        
        return hash('sha256', $content);
    }
    
    public function verify_file_integrity($file_path, $expected_hash) {
        $current_hash = $this->get_file_integrity_hash($file_path);
        
        if ($current_hash === false) {
            return false;
        }
        
        return $current_hash === $expected_hash;
    }
    
    public function get_scan_summary($scan_id = null) {
        if ($scan_id === null) {
            $scan_id = $this->scan_id;
        }
        
        $results = $this->database->get_scan_results($scan_id);
        
        $summary = array(
            'scan_id' => $scan_id,
            'total_threats' => count($results),
            'critical_threats' => 0,
            'high_threats' => 0,
            'medium_threats' => 0,
            'low_threats' => 0,
            'threat_types' => array(),
            'affected_files' => array()
        );
        
        foreach ($results as $result) {
            $summary[$result->threat_severity . '_threats']++;
            
            if (!isset($summary['threat_types'][$result->threat_type])) {
                $summary['threat_types'][$result->threat_type] = 0;
            }
            $summary['threat_types'][$result->threat_type]++;
            
            if (!in_array($result->file_path, $summary['affected_files'])) {
                $summary['affected_files'][] = $result->file_path;
            }
        }
        
        return $summary;
    }
}