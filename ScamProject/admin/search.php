<?php
session_start();
require_once "../../Database/database.php";

$keyword = $_GET['keyword'] ?? '';

/* =========================
LOG SEARCH ACTIVITY
========================= */

$user_id = $_SESSION['user_id'] ?? NULL;
$username = $_SESSION['user_name'] ?? 'Guest';
$role = $_SESSION['role'] ?? 'Guest';

$ip = $_SERVER['REMOTE_ADDR'];
$user_agent = $_SERVER['HTTP_USER_AGENT'];

$action = "Search";
$target = "Keyword: ".$keyword;

$stmt = $conn->prepare("
INSERT INTO activity_logs
(user_id, username, role, action, target, ip_address, user_agent)
VALUES (?,?,?,?,?,?,?)
");

$stmt->bind_param(
"issssss",
$user_id,
$username,
$role,
$action,
$target,
$ip,
$user_agent
);

$stmt->execute();

if(!$keyword){
die("No search keyword");
}

/* SEARCH USERS */

$user_query = mysqli_query($conn,"
SELECT 'User' as type, username as result, id
FROM users
WHERE username LIKE '%$keyword%'
");

/* SEARCH PHONE NUMBERS */

$phone_query = mysqli_query($conn,"
SELECT 'Phone' as type, phonenumber as result, id
FROM phonenumbers
WHERE phonenumber LIKE '%$keyword%'
");

/* SEARCH REPORTS */

$report_query = mysqli_query($conn,"
SELECT 'Report' as type, phone as result, id
FROM reports
WHERE phone LIKE '%$keyword%'
");

/* SEARCH ACTIVITY LOGS */

$log_query = mysqli_query($conn,"
SELECT 'Activity' as type, action as result, id
FROM activity_logs
WHERE action LIKE '%$keyword%'
");
?>

<h2>Search Result</h2>

<table class="table table-bordered">

<tr>
<th>Type</th>
<th>Result</th>
</tr>

<?php

while($row=mysqli_fetch_assoc($user_query)){
echo "<tr><td>User</td><td>".$row['result']."</td></tr>";
}

while($row=mysqli_fetch_assoc($phone_query)){
echo "<tr><td>Phone</td><td>".$row['result']."</td></tr>";
}

while($row=mysqli_fetch_assoc($report_query)){
echo "<tr><td>Report</td><td>".$row['result']."</td></tr>";
}

while($row=mysqli_fetch_assoc($log_query)){
echo "<tr><td>Activity</td><td>".$row['result']."</td></tr>";
}

?>

</table>