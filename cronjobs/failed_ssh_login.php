#!/usr/bin/php
<?php
// File: cronjobs/failed_ssh_login.php

// Change to the working directory
chdir(dirname(__FILE__));

require_once "../include/db.php";

function extractFailedIPs($logFile, $conn) {
    // Check if the log file exists
    if (!file_exists($logFile)) {
        error_log("Log file not found: $logFile");
        echo "Log file missing. Please verify the path.";
        return; // Exit the function gracefully
    }

    error_log("Processing log file: $logFile");

    // Read the log file line by line
    $logContent = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    // Loop through log lines to find failed SSH attempts
    foreach ($logContent as $line) {
        if (strpos($line, 'Failed password for') !== false) {
            // Extract IP address after "from"
            preg_match('/from ((?:\d{1,3}\.){3}\d{1,3}|(?:[a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4})/', $line, $matches);

            if (!empty($matches)) {
                $ip = $matches[1]; // Use the captured IP
                error_log("Extracted IP: $ip");

                // Use INSERT IGNORE to avoid duplicates (Database-level check)
                $stmtInsert = $conn->prepare("INSERT IGNORE INTO failed_ips (ip_address) VALUES (?)");
                $stmtInsert->bind_param("s", $ip);
                $stmtInsert->execute();
                $stmtInsert->close();
            }
        }
    }

    echo "IPs successfully extracted and stored.";
}

// Path to the auth log file
$logFile = '/var/log/auth.log';
extractFailedIPs($logFile, $conn);

$conn->close();
?>
