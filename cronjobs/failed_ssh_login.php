#!/usr/bin/php
<?php
// File: cronjobs/failed_ssh_login.php

chdir(dirname(__FILE__));
require_once "../include/db.php";

// Path to the auth log file
$logFile = '/var/log/auth.log';

// Check if the log file exists
if (!file_exists($logFile)) {
    echo "Log file missing. Please verify the path.\n";
    exit(1);
}

// Step 1: Extract IPs from the log file
$logContent = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$ipSet = [];

// Regex for IPv4 or IPv6
$ipRegex = '/from ([0-9a-fA-F\.:]+)/';

foreach ($logContent as $line) {
    // Match both:
    // "Failed password for root"
    // "Failed password for invalid user admin"
    if (strpos($line, 'Failed password for') !== false) {
        if (preg_match($ipRegex, $line, $matches)) {
            $ip = trim($matches[1]);
            if ($ip !== '') {
                $ipSet[$ip] = true;
            }
        }
    }
}

// Step 2: Clear the table
$truncateQuery = "TRUNCATE TABLE failed_ips";
if ($conn->query($truncateQuery) === TRUE) {
    echo "Table successfully cleared.\n";
} else {
    echo "Error clearing table: " . $conn->error . "\n";
    exit(1);
}

// Step 3: Insert current IPs
$stmtInsert = $conn->prepare("INSERT INTO failed_ips (ip_address) VALUES (?)");

foreach (array_keys($ipSet) as $ip) {
    $stmtInsert->bind_param("s", $ip);
    $stmtInsert->execute();
}

$stmtInsert->close();
$conn->close();

echo "Current IPs successfully synced from log.\n";
?>
