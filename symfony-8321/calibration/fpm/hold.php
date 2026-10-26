<?php

// Lab-only calibration endpoint. It keeps the request alive long enough for a
// read-only debugger to inspect the FPM worker after multipart parsing.
session_start();
sleep(90);
echo "CALIBRATION_HOLD_OK\n";
