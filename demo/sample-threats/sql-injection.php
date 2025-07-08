<?php
// Demo file: SQL injection patterns
$query = "SELECT * FROM wp_users WHERE user_login = '" . $_POST['username'] . "'";
$injection = "UNION SELECT user_login, user_pass FROM wp_users WHERE 1=1";
$info_schema = "SELECT table_name FROM information_schema.tables";
?>