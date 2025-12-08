"""
Feature Extraction Module for PHP Malware Detection

This module extracts numerical features from PHP code for machine learning
classification. Features are designed to capture patterns commonly associated
with malicious code.

Feature Categories:
1. Lexical Features (function calls, variable patterns)
2. Statistical Features (entropy, character distribution)
3. Structural Features (code complexity metrics)
4. Behavioral Features (suspicious patterns)
5. WordPress-Specific Features (hooks, capabilities)
"""

import re
import math
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import numpy as np


@dataclass
class FeatureVector:
    """Container for extracted features with metadata."""
    features: np.ndarray
    feature_names: List[str]
    file_path: str
    extraction_time_ms: float


class PHPFeatureExtractor:
    """
    Extract ML features from PHP source code.

    This extractor generates a fixed-size feature vector suitable for
    traditional ML models (Random Forest, XGBoost, etc.).
    """

    # Dangerous PHP functions by category
    DANGEROUS_FUNCTIONS = {
        'execution': ['eval', 'exec', 'shell_exec', 'system', 'passthru',
                     'popen', 'proc_open', 'pcntl_exec'],
        'file_ops': ['file_get_contents', 'file_put_contents', 'fopen',
                    'fwrite', 'fread', 'unlink', 'rename', 'copy', 'move_uploaded_file'],
        'network': ['curl_exec', 'curl_multi_exec', 'fsockopen', 'socket_connect',
                   'stream_socket_client'],
        'encoding': ['base64_decode', 'base64_encode', 'str_rot13',
                    'gzinflate', 'gzuncompress', 'gzdecode', 'convert_uudecode'],
        'reflection': ['create_function', 'call_user_func', 'call_user_func_array',
                      'preg_replace_callback', 'array_map', 'array_filter']
    }

    # WordPress-specific patterns
    WP_DANGEROUS_PATTERNS = [
        r'wp_users.*password',
        r'user_pass\s*=',
        r'\$wpdb->query.*DELETE',
        r'\$wpdb->query.*DROP',
        r'add_user|wp_insert_user|wp_create_user',
        r'update_option.*admin',
        r'wp_set_auth_cookie',
    ]

    # Obfuscation indicators
    OBFUSCATION_PATTERNS = [
        r'\\x[0-9a-fA-F]{2}',  # Hex escapes
        r'chr\s*\(\s*\d+\s*\)',  # Character codes
        r'\$\w+\s*\.\s*\$\w+\s*\.\s*\$\w+',  # Variable concatenation chains
        r'for\s*\(.*?chr\s*\(',  # Character building loops
        r'preg_replace.*\/e',  # Deprecated eval modifier
    ]

    def __init__(self, feature_count: int = 100):
        """
        Initialize the feature extractor.

        Args:
            feature_count: Number of features to extract (for compatibility)
        """
        self.feature_count = feature_count
        self.feature_names = self._build_feature_names()

    def _build_feature_names(self) -> List[str]:
        """Build list of feature names for interpretability."""
        names = []

        # Lexical features (0-29)
        for category, funcs in self.DANGEROUS_FUNCTIONS.items():
            for func in funcs[:5]:  # Top 5 per category
                names.append(f'func_{category}_{func}')

        # Statistical features (30-49)
        names.extend([
            'entropy', 'entropy_normalized',
            'avg_line_length', 'max_line_length',
            'num_lines', 'num_chars',
            'alpha_ratio', 'digit_ratio', 'special_ratio',
            'whitespace_ratio', 'uppercase_ratio',
            'avg_word_length', 'max_word_length',
            'unique_char_count', 'char_diversity',
            'long_string_count', 'hex_escape_count',
            'base64_candidate_count', 'unicode_escape_count',
            'compression_ratio'
        ])

        # Structural features (50-69)
        names.extend([
            'function_count', 'class_count',
            'variable_count', 'unique_variable_count',
            'max_nesting_depth', 'avg_nesting_depth',
            'comment_ratio', 'code_to_comment_ratio',
            'include_count', 'require_count',
            'try_catch_count', 'if_count',
            'loop_count', 'switch_count',
            'return_count', 'echo_count',
            'print_count', 'die_exit_count',
            'namespace_present', 'use_statement_count'
        ])

        # Behavioral features (70-84)
        names.extend([
            'user_input_access', 'server_var_access',
            'session_access', 'cookie_access',
            'file_upload_handling', 'db_query_count',
            'external_url_count', 'ip_address_count',
            'email_pattern_count', 'shell_command_pattern',
            'sql_pattern_count', 'credential_pattern',
            'backdoor_indicator', 'webshell_indicator',
            'crypto_mining_indicator'
        ])

        # WordPress-specific features (85-99)
        names.extend([
            'wp_hook_count', 'wp_filter_count',
            'wp_action_count', 'wp_nonce_check',
            'wp_capability_check', 'wp_user_manipulation',
            'wp_option_manipulation', 'wp_db_direct_query',
            'wp_file_editor_pattern', 'wp_plugin_pattern',
            'wp_theme_pattern', 'wp_admin_pattern',
            'wp_ajax_pattern', 'wp_rest_pattern',
            'wp_cron_pattern'
        ])

        return names[:self.feature_count]

    def extract(self, code: str, file_path: str = '') -> FeatureVector:
        """
        Extract features from PHP code.

        Args:
            code: PHP source code string
            file_path: Optional file path for context

        Returns:
            FeatureVector with extracted features
        """
        import time
        start_time = time.time()

        features = np.zeros(self.feature_count, dtype=np.float32)
        idx = 0

        # Lexical features
        idx = self._extract_lexical_features(code, features, idx)

        # Statistical features
        idx = self._extract_statistical_features(code, features, idx)

        # Structural features
        idx = self._extract_structural_features(code, features, idx)

        # Behavioral features
        idx = self._extract_behavioral_features(code, features, idx)

        # WordPress-specific features
        idx = self._extract_wordpress_features(code, features, idx)

        extraction_time = (time.time() - start_time) * 1000

        return FeatureVector(
            features=features,
            feature_names=self.feature_names,
            file_path=file_path,
            extraction_time_ms=extraction_time
        )

    def _extract_lexical_features(self, code: str, features: np.ndarray, idx: int) -> int:
        """Extract function call and lexical features."""
        code_lower = code.lower()

        for category, funcs in self.DANGEROUS_FUNCTIONS.items():
            for func in funcs[:5]:
                pattern = rf'\b{re.escape(func)}\s*\('
                count = len(re.findall(pattern, code_lower))
                features[idx] = min(count, 10)  # Cap at 10
                idx += 1

        return idx

    def _extract_statistical_features(self, code: str, features: np.ndarray, idx: int) -> int:
        """Extract statistical and entropy-based features."""

        # Entropy calculation
        entropy = self._calculate_entropy(code)
        features[idx] = entropy
        idx += 1
        features[idx] = entropy / 8.0  # Normalized (max entropy = 8 bits)
        idx += 1

        # Line statistics
        lines = code.split('\n')
        line_lengths = [len(line) for line in lines]
        features[idx] = np.mean(line_lengths) if line_lengths else 0
        idx += 1
        features[idx] = max(line_lengths) if line_lengths else 0
        idx += 1
        features[idx] = len(lines)
        idx += 1
        features[idx] = len(code)
        idx += 1

        # Character type ratios
        if len(code) > 0:
            features[idx] = sum(c.isalpha() for c in code) / len(code)
            idx += 1
            features[idx] = sum(c.isdigit() for c in code) / len(code)
            idx += 1
            features[idx] = sum(not c.isalnum() and not c.isspace() for c in code) / len(code)
            idx += 1
            features[idx] = sum(c.isspace() for c in code) / len(code)
            idx += 1
            features[idx] = sum(c.isupper() for c in code) / len(code)
            idx += 1
        else:
            idx += 5

        # Word statistics
        words = re.findall(r'\b\w+\b', code)
        if words:
            word_lengths = [len(w) for w in words]
            features[idx] = np.mean(word_lengths)
            idx += 1
            features[idx] = max(word_lengths)
            idx += 1
        else:
            idx += 2

        # Character diversity
        unique_chars = len(set(code))
        features[idx] = unique_chars
        idx += 1
        features[idx] = unique_chars / 256.0  # Normalized
        idx += 1

        # Obfuscation indicators
        features[idx] = len(re.findall(r'[a-zA-Z0-9+/=]{50,}', code))  # Long strings
        idx += 1
        features[idx] = len(re.findall(r'\\x[0-9a-fA-F]{2}', code))  # Hex escapes
        idx += 1
        features[idx] = len(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', code))  # Base64
        idx += 1
        features[idx] = len(re.findall(r'\\u[0-9a-fA-F]{4}', code))  # Unicode
        idx += 1

        # Compression ratio (approximation)
        try:
            import zlib
            compressed = zlib.compress(code.encode('utf-8', errors='ignore'))
            features[idx] = len(compressed) / max(len(code), 1)
        except:
            features[idx] = 0.5
        idx += 1

        return idx

    def _extract_structural_features(self, code: str, features: np.ndarray, idx: int) -> int:
        """Extract code structure features."""

        # Function and class counts
        features[idx] = len(re.findall(r'\bfunction\s+\w+\s*\(', code))
        idx += 1
        features[idx] = len(re.findall(r'\bclass\s+\w+', code))
        idx += 1

        # Variable counts
        variables = re.findall(r'\$\w+', code)
        features[idx] = len(variables)
        idx += 1
        features[idx] = len(set(variables))
        idx += 1

        # Nesting depth (approximate)
        max_depth = 0
        current_depth = 0
        for char in code:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth = max(0, current_depth - 1)
        features[idx] = max_depth
        idx += 1
        features[idx] = max_depth / max(code.count('{'), 1)  # Average depth
        idx += 1

        # Comment ratio
        comment_lines = len(re.findall(r'//.*$|/\*.*?\*/', code, re.MULTILINE | re.DOTALL))
        total_lines = len(code.split('\n'))
        features[idx] = comment_lines / max(total_lines, 1)
        idx += 1
        features[idx] = (total_lines - comment_lines) / max(comment_lines, 1)
        idx += 1

        # Control structures
        features[idx] = len(re.findall(r'\binclude\b', code))
        idx += 1
        features[idx] = len(re.findall(r'\brequire\b', code))
        idx += 1
        features[idx] = len(re.findall(r'\btry\s*\{', code))
        idx += 1
        features[idx] = len(re.findall(r'\bif\s*\(', code))
        idx += 1
        features[idx] = len(re.findall(r'\b(for|foreach|while)\s*\(', code))
        idx += 1
        features[idx] = len(re.findall(r'\bswitch\s*\(', code))
        idx += 1
        features[idx] = len(re.findall(r'\breturn\b', code))
        idx += 1
        features[idx] = len(re.findall(r'\becho\b', code))
        idx += 1
        features[idx] = len(re.findall(r'\bprint\b', code))
        idx += 1
        features[idx] = len(re.findall(r'\b(die|exit)\s*\(', code))
        idx += 1

        # Namespace and use statements
        features[idx] = 1 if re.search(r'\bnamespace\s+', code) else 0
        idx += 1
        features[idx] = len(re.findall(r'\buse\s+[\w\\]+', code))
        idx += 1

        return idx

    def _extract_behavioral_features(self, code: str, features: np.ndarray, idx: int) -> int:
        """Extract behavioral pattern features."""

        # User input access
        features[idx] = len(re.findall(r'\$_(GET|POST|REQUEST)\s*\[', code))
        idx += 1
        features[idx] = len(re.findall(r'\$_SERVER\s*\[', code))
        idx += 1
        features[idx] = len(re.findall(r'\$_SESSION\s*\[', code))
        idx += 1
        features[idx] = len(re.findall(r'\$_COOKIE\s*\[', code))
        idx += 1

        # File upload handling
        features[idx] = len(re.findall(r'\$_FILES|move_uploaded_file', code))
        idx += 1

        # Database queries
        features[idx] = len(re.findall(r'mysql_query|mysqli_query|\$wpdb->query', code))
        idx += 1

        # External URLs
        features[idx] = len(re.findall(r'https?://[^\s\'"]+', code))
        idx += 1

        # IP addresses
        features[idx] = len(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', code))
        idx += 1

        # Email patterns
        features[idx] = len(re.findall(r'[\w.-]+@[\w.-]+\.\w+', code))
        idx += 1

        # Shell command patterns
        features[idx] = 1 if re.search(r'(exec|shell_exec|system|passthru)\s*\(\s*\$', code) else 0
        idx += 1

        # SQL patterns
        features[idx] = len(re.findall(r'(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+', code, re.I))
        idx += 1

        # Credential patterns
        features[idx] = len(re.findall(r'(password|passwd|pwd|secret|token|api_key)', code, re.I))
        idx += 1

        # Backdoor indicators
        backdoor_patterns = [
            r'c99|r57|b374k|wso\d*|alfa|angel|indoxploit',
            r'FilesMan|Hacked|Pwned|Shell',
            r'@fsockopen|@pfsockopen'
        ]
        features[idx] = 1 if any(re.search(p, code, re.I) for p in backdoor_patterns) else 0
        idx += 1

        # Webshell indicators
        webshell_patterns = [
            r'passthru\s*\(\s*\$_',
            r'eval\s*\(\s*\$_',
            r'system\s*\(\s*\$_',
            r'assert\s*\(\s*\$_'
        ]
        features[idx] = 1 if any(re.search(p, code) for p in webshell_patterns) else 0
        idx += 1

        # Crypto mining indicators
        crypto_patterns = [
            r'coinhive|cryptonight|monero|stratum',
            r'CoinImp|JSEcoin|Crypto-?Loot',
            r'wasm|WebAssembly'
        ]
        features[idx] = 1 if any(re.search(p, code, re.I) for p in crypto_patterns) else 0
        idx += 1

        return idx

    def _extract_wordpress_features(self, code: str, features: np.ndarray, idx: int) -> int:
        """Extract WordPress-specific features."""

        # Hook and filter usage
        features[idx] = len(re.findall(r'add_action\s*\(', code))
        idx += 1
        features[idx] = len(re.findall(r'add_filter\s*\(', code))
        idx += 1
        features[idx] = len(re.findall(r'do_action\s*\(', code))
        idx += 1

        # Security checks
        features[idx] = len(re.findall(r'wp_verify_nonce|check_admin_referer', code))
        idx += 1
        features[idx] = len(re.findall(r'current_user_can|user_can', code))
        idx += 1

        # User manipulation
        features[idx] = len(re.findall(r'wp_insert_user|wp_update_user|wp_create_user', code))
        idx += 1

        # Option manipulation
        features[idx] = len(re.findall(r'update_option|add_option|delete_option', code))
        idx += 1

        # Direct database queries
        features[idx] = len(re.findall(r'\$wpdb->(query|get_|insert|update|delete)', code))
        idx += 1

        # Sensitive patterns
        features[idx] = 1 if re.search(r'plugin_editor|theme_editor', code, re.I) else 0
        idx += 1
        features[idx] = len(re.findall(r'register_activation_hook|register_deactivation_hook', code))
        idx += 1
        features[idx] = len(re.findall(r'wp_enqueue_script|wp_enqueue_style', code))
        idx += 1
        features[idx] = 1 if re.search(r'is_admin\s*\(\s*\)', code) else 0
        idx += 1
        features[idx] = len(re.findall(r'wp_ajax_|admin_post_', code))
        idx += 1
        features[idx] = len(re.findall(r'register_rest_route|WP_REST', code))
        idx += 1
        features[idx] = len(re.findall(r'wp_schedule_event|wp_cron', code))
        idx += 1

        return idx

    def _calculate_entropy(self, data: str) -> float:
        """
        Calculate Shannon entropy of a string.

        H(X) = -sum(p(x) * log2(p(x))) for all x in X

        Args:
            data: Input string

        Returns:
            Entropy value in bits per byte (0-8)
        """
        if not data:
            return 0.0

        # Count byte frequencies
        byte_counts: Dict[int, int] = {}
        for byte in data.encode('utf-8', errors='ignore'):
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        # Calculate entropy
        length = len(data)
        entropy = 0.0

        for count in byte_counts.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return entropy


def extract_features_batch(
    files: List[Tuple[str, str]],
    extractor: Optional[PHPFeatureExtractor] = None
) -> Tuple[np.ndarray, List[str]]:
    """
    Extract features from multiple files.

    Args:
        files: List of (file_path, content) tuples
        extractor: Optional pre-configured extractor

    Returns:
        Tuple of (feature_matrix, file_paths)
    """
    if extractor is None:
        extractor = PHPFeatureExtractor()

    features_list = []
    file_paths = []

    for file_path, content in files:
        try:
            fv = extractor.extract(content, file_path)
            features_list.append(fv.features)
            file_paths.append(file_path)
        except Exception as e:
            print(f"Error extracting features from {file_path}: {e}")

    return np.array(features_list), file_paths


if __name__ == '__main__':
    # Example usage
    sample_code = '''<?php
    eval(base64_decode($_POST['cmd']));
    $result = shell_exec($_GET['command']);
    echo $result;
    ?>'''

    extractor = PHPFeatureExtractor()
    fv = extractor.extract(sample_code, 'test.php')

    print(f"Extracted {len(fv.features)} features in {fv.extraction_time_ms:.2f}ms")
    print("\nTop features:")
    for name, value in zip(fv.feature_names[:20], fv.features[:20]):
        if value > 0:
            print(f"  {name}: {value}")
