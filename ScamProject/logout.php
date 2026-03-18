<?php
session_start();
require_once '../Database/database.php';

if(isset($_SESSION['user_id'])){

$user_id = $_SESSION['user_id'];

$stmt = $conn->prepare("UPDATE users SET status='Inactive' WHERE id=?");
$stmt->bind_param("i",$user_id);
$stmt->execute();

}

session_destroy();

header("Location: login.php");
exit();
?>