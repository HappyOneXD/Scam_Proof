<?php
session_start();
require '../Database/database.php';

$otp = "";
$message = "";

if(isset($_POST['check_user'])){

    $username = trim($_POST['username']);

    $sql = "SELECT * FROM users WHERE username=?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s",$username);
    $stmt->execute();
    $result = $stmt->get_result();

    if($result->num_rows > 0){

        $otp = rand(100000,999999);

        $_SESSION['reset_user'] = $username;
        $_SESSION['otp'] = $otp;

    }else{
        $message = "Username not found!";
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">

    <title>Forgot Password</title>

    <style>
    body {
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
        margin: 0;
    }

    .overlay {
        background: rgba(0, 0, 0, 0.55);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
    }

    .form-box {
        max-width: 450px;
        width: 100%;
        background: rgba(0, 0, 0, 0.6);
        padding: 30px;
        border-radius: 10px;
    }
    </style>

</head>

<body>

    <div class="overlay">

        <div class="form-box">

            <h3 class="mb-4 text-center">Forgot Password</h3>

            <?php if($message!=""){ ?>
            <div class="alert alert-danger">
                <?php echo htmlspecialchars($message); ?>
            </div>
            <?php } ?>

            <form method="POST">

                <input type="text" name="username" class="form-control mb-3" placeholder="Enter username" required>

                <button name="check_user" class="btn btn-primary w-100">
                    <i class="bi bi-send"></i> Send OTP
                </button>

            </form>

            <?php if($otp!=""){ ?>

            <hr>

            <div class="alert alert-warning">
                OTP generated (Demo only): <b id="otpText"><?php echo $otp; ?></b>
            </div>

            <form action="verify_otp.php" method="POST">

                <input type="text" id="otpInput" name="otp" class="form-control mb-3" placeholder="Enter OTP" required>

                <button class="btn btn-success w-100">
                    Verify OTP
                </button>

            </form>

            <?php } ?>

        </div>

    </div>

</body>

</html>

<script>
let otpText = document.getElementById("otpText");
let otpInput = document.getElementById("otpInput");

if (otpText && otpInput) {
    otpInput.value = otpText.innerText;
}
</script>