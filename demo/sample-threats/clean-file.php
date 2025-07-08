<?php
// Demo file: clean file (should not be detected)
function get_user_data($user_id) {
    global $wpdb;
    return $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->users} WHERE ID = %d", $user_id));
}

function sanitize_user_input($input) {
    return sanitize_text_field($input);
}

echo "This is a clean WordPress file with no security threats.";
?>