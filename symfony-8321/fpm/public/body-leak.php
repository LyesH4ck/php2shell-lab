<?php

// Lab-only sink used to validate a same-request body disclosure. Multipart
// parsing (and therefore the stale decoder primitive) has already completed
// when this script starts. The BIG zval is deliberately consumed only here.
header('Content-Type: application/octet-stream');
header('Cache-Control: no-store');
header('X-Lab-Worker-Pid: ' . getmypid());

$hold = min(180, max(0, (int) ($_GET['hold'] ?? 0)));
if ($hold > 0) {
    echo "CALIBRATION " . getmypid() . "\n";
    flush();
    sleep($hold);
}

echo "P2S-LEAK-BEGIN\n";
echo $_POST['BIG'] ?? '';
echo "\nP2S-LEAK-END\n";
