<?php
session_start();

if(isset($_POST['otp'])){

$user_otp = $_POST['otp'];

if($user_otp == $_SESSION['otp']){

header("Location: reset_password.php");
exit;

}else{

echo "Wrong OTP";

}

}
?>