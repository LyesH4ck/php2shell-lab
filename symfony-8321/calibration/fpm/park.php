<?php

// Lab-only worker fence. Each request occupies exactly one FPM child while
// emitting a heartbeat so nginx does not hit fastcgi_read_timeout.
header('Content-Type: text/plain');
header('Cache-Control: no-store');
header('X-Accel-Buffering: no');
header('X-Lab-Worker-Pid: ' . getmypid());

while (ob_get_level() > 0) {
    ob_end_flush();
}

echo "PARK " . getmypid() . "\n";
flush();

$deadline = time() + 1800;
while (time() < $deadline) {
    echo ".\n";
    flush();
    sleep(1);
    if (connection_aborted()) {
        break;
    }
}

