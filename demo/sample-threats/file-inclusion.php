<?php
// Demo file: file inclusion vulnerability
$file = $_GET['file'];
include($file);
?>