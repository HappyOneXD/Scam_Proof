<?php
session_start();
require '../Database/database.php';
require_once 'functions/translate.php';

// Language switch
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en','vi'])) {
    $_SESSION['lang'] = $_GET['lang'];
    $currentPage = strtok($_SERVER["REQUEST_URI"], '?');
    header("Location: $currentPage");
    exit;
}
$lang = $_SESSION['lang'] ?? 'en';

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
        $message = t("Username not found!");
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

    <title><?php echo t("Forgot Password");?></title>

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

    .lang-btn {
        display: flex;
        align-items: center;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.85rem;
        font-weight: 600;
        text-decoration: none;
        transition: all 0.3s ease;
        background: #f8f9fa;
        color: #334155;
        border: 1px solid #e2e8f0;
    }
    .lang-btn.active {
        background: #0ea5e9;
        color: white;
        border-color: #0ea5e9;
        box-shadow: 0 0 10px rgba(14,165,233,0.4);
    }
    .flag-img {
        width: 20px;
        height: 15px;
        object-fit: cover;
        border-radius: 2px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .lang-btn:hover:not(.active) {
        background: #e2e8f0;
        transform: translateY(-1px);
    }
    </style>

</head>

<body>

    <div class="overlay">

        <?php $lang = $_SESSION['lang'] ?? 'en'; ?>
        <div class="lang-switch position-absolute top-0 end-0 m-3 d-flex gap-2">
            <a href="?lang=en" class="lang-btn <?php echo $lang=='en' ? 'active' : ''; ?>">
                <img src="https://flagcdn.com/w40/gb.png" class="flag-img" alt="English">
                <span class="ms-1">EN</span>
            </a>

            <a href="?lang=vi" class="lang-btn <?php echo $lang=='vi' ? 'active' : ''; ?>">
                <img src="https://flagcdn.com/w40/vn.png" class="flag-img" alt="Vietnamese">
                <span class="ms-1">VI</span>
            </a>
        </div>

        <div class="form-box">

            <h3 class="mb-4 text-center"><?php echo t("Forgot Password");?></h3>

            <?php if($message!=""){ ?>
            <div class="alert alert-danger">
                <?php echo htmlspecialchars($message); ?>
            </div>
            <?php } ?>

            <form method="POST">

                <input type="text" name="username" class="form-control mb-3"
                       placeholder="<?php echo t('Enter username');?>" required>

                <button name="check_user" class="btn btn-primary w-100">
                    <i class="bi bi-send"></i> <?php echo t("Send OTP");?>
                </button>

            </form>

            <?php if($otp!=""){ ?>

            <hr>

            <div class="alert alert-warning">
                <?php echo t("OTP generated (demo only):");?> <b id="otpText"><?php echo $otp; ?></b>
            </div>

            <form action="verify_otp.php" method="POST">

                <input type="text" id="otpInput" name="otp" class="form-control mb-3"
                       placeholder="<?php echo t('Enter OTP');?>" required>

                <button class="btn btn-success w-100">
                    <?php echo t("Verify OTP");?>
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
