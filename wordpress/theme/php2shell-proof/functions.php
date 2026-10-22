<?php

// Keep /index.php stable for the exploit and its post-RCE follow-up probe.
remove_filter('template_redirect', 'redirect_canonical');
