<?php
// Demo file: Comprehensive PHP injection techniques
// This file demonstrates various injection vectors that should be detected

// 1. Direct code injection
if (isset($_POST['code'])) {
    eval($_POST['code']);
}

// 2. File inclusion vulnerabilities
if (isset($_GET['page'])) {
    include($_GET['page']);
}

// 3. SQL injection patterns
function unsafe_query($user_id) {
    global $wpdb;
    $query = "SELECT * FROM wp_users WHERE ID = " . $_GET['id'];
    return $wpdb->get_results($query);
}

// 4. Command injection
if (isset($_POST['ping_host'])) {
    $host = $_POST['ping_host'];
    system("ping -c 1 $host");
}

// 5. XML External Entity (XXE) injection
if (isset($_POST['xml_data'])) {
    $xml = $_POST['xml_data'];
    $dom = new DOMDocument();
    $dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
}

// 6. Unserialize injection
if (isset($_COOKIE['user_data'])) {
    $user_data = unserialize($_COOKIE['user_data']);
}

// 7. LDAP injection
function ldap_search_user($username) {
    $filter = "(uid=$username)";
    return ldap_search($connection, $base_dn, $filter);
}

// 8. Path traversal
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    readfile("/var/www/uploads/" . $file);
}

// 9. Server-Side Request Forgery (SSRF)
if (isset($_POST['url'])) {
    $url = $_POST['url'];
    $content = file_get_contents($url);
    echo $content;
}

// 10. Template injection
if (isset($_POST['template'])) {
    $template = $_POST['template'];
    eval('echo "' . $template . '";');
}

// 11. Header injection
if (isset($_GET['redirect'])) {
    header("Location: " . $_GET['redirect']);
}

// 12. XPath injection
if (isset($_POST['search'])) {
    $search = $_POST['search'];
    $xpath = "//user[name='$search']";
    $result = $dom->xpath($xpath);
}

// 13. NoSQL injection (MongoDB)
if (isset($_POST['mongo_query'])) {
    $query = $_POST['mongo_query'];
    $collection->findOne(eval("return $query;"));
}

// 14. Expression Language injection
if (isset($_POST['expression'])) {
    $expr = $_POST['expression'];
    eval("\$result = $expr;");
}

// 15. Mass assignment vulnerability
if (isset($_POST['user_data'])) {
    foreach ($_POST['user_data'] as $key => $value) {
        $user->$key = $value; // Dangerous mass assignment
    }
}

// 16. Insecure deserialization
class UnsafeClass {
    public function __wakeup() {
        eval($this->command);
    }
}

// 17. File upload bypass
if (isset($_FILES['upload'])) {
    $filename = $_FILES['upload']['name'];
    move_uploaded_file($_FILES['upload']['tmp_name'], "/uploads/" . $filename);
}

// 18. Race condition exploitation
$lock_file = '/tmp/race_condition';
if (!file_exists($lock_file)) {
    file_put_contents($lock_file, '1');
    // Vulnerable operation here
    unlink($lock_file);
}

// 19. Integer overflow
if (isset($_GET['amount'])) {
    $amount = (int)$_GET['amount'];
    $total = $amount * 1000000; // Potential overflow
}

// 20. Format string vulnerability
if (isset($_POST['log_message'])) {
    $message = $_POST['log_message'];
    error_log(sprintf($message, "additional", "parameters"));
}
?>