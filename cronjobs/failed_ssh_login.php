#!/usr/bin/php
<?php
// File: cronjobs/failed_ssh_login.php

// Change to the working directory
chdir(dirname(__FILE__));

// Include dependencies
require_once "../include/db.php";


// Path to the auth log file
$logFile = '/var/log/auth.log';

// Connect to the database
$conn = new conn($host, $user, $password, $dbname);

// Check the database connection
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

// Function to extract IPs from the log file and store in the database
function extractFailedIPs($logFile, $conn) {
    if (file_exists($logFile)) {
        $logContent = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        // Loop through log lines to find failed SSH attempts
        foreach ($logContent as $line) {
            if (strpos($line, 'Failed password for') !== false) {
                // Extract both IPv4 and IPv6 using regex
                preg_match('/((\d{1,3}\.){3}\d{1,3}|([a-f0-9:]+:+)+[a-f0-9]+)/i', $line, $matches);

                if (!empty($matches)) {
                    $ip = $matches[0];

                    // Check if the IP is already in the database
                    $stmtCheck = $conn->prepare("SELECT COUNT(*) FROM failed_ips WHERE ip_address = ?");
                    $stmtCheck->bind_param("s", $ip);
                    $stmtCheck->execute();
                    $stmtCheck->bind_result($count);
                    $stmtCheck->fetch();
                    $stmtCheck->close();

                    // Insert IP if it's not already recorded
                    if ($count == 0) {
                        $stmtInsert = $conn->prepare("INSERT INTO failed_ips (ip_address) VALUES (?)");
                        $stmtInsert->bind_param("s", $ip);
                        $stmtInsert->execute();
                        $stmtInsert->close();
                    }
                }
            }
        }

        echo "IPs successfully extracted and stored.";
    } else {
        echo "Log file not found!";
    }
}

// Call the function to process the log file
extractFailedIPs($logFile, $conn);

// Close the database connection
$conn->close();
?>