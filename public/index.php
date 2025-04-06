<?php
// File: public/index.php

require_once "../include/db.php";

// Fetch IP addresses from the database
$query = "SELECT ip_address FROM failed_ips ORDER BY timestamp DESC";
$result = $conn->query($query);

// Check if there are rows to display
if ($result->num_rows > 0) {
    // Output each IP address on a new line
    while ($row = $result->fetch_assoc()) {
        echo htmlspecialchars($row['ip_address']) . "<br>";
    }
} else {
    echo "No failed login attempts found.";
}

// Close the database connection
$conn->close();
?>
