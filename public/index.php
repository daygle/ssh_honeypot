<?php
// File: public/index.php

require_once "../include/db.php"; // Include the database connection

// Fetch IP addresses from the database
$query = "SELECT ip_address FROM failed_ips ORDER BY timestamp DESC";
$result = $conn->query($query);

// Check if the query execution succeeded
if (!$result) {
    error_log("Database query failed: " . $conn->error); // Log the error
    die("An error occurred while retrieving data. Please try again later."); // Generic error message for the user
}

// Check if there are rows to display
if ($result->num_rows > 0) {
    // Output each IP address on a new line
    while ($row = $result->fetch_assoc()) {
        echo htmlspecialchars($row['ip_address']) . "<br>"; // Escape for security
    }
} else {
    echo "No failed login attempts found."; // Message for empty results
}

// Close the database connection
$conn->close();
?>