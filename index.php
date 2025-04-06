<?php
// Path to the auth log file
$logFile = '/var/log/auth.log';

// Open the file for reading
if (file_exists($logFile)) {
    $logContent = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    // Array to store failed attempt IPs
    $failedIPs = [];

    // Loop through each line of the log file
    foreach ($logContent as $line) {
        // Look for lines indicating failed SSH attempts
        if (strpos($line, 'Failed password for') !== false) {
            // Extract the IP address using regex
            preg_match('/(\d{1,3}\.){3}\d{1,3}/', $line, $matches);

            // Add the IP to the array if found
            if (!empty($matches)) {
                $failedIPs[] = $matches[0];
            }
        }
    }

    // Remove duplicate IPs
    $failedIPs = array_unique($failedIPs);

    // Display the IPs
    echo "<h1>Failed SSH Attempt IPs:</h1>";
    echo "<ul>";
    foreach ($failedIPs as $ip) {
        echo "<li>$ip</li>";
    }
    echo "</ul>";

} else {
    echo "Log file not found!";
}
?>
