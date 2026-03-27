<?php
session_start();
require '../Database/database.php';
require_once 'functions/translate.php';

// language switch
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en','vi'])) {
    $_SESSION['lang'] = $_GET['lang'];
    $currentPage = strtok($_SERVER["REQUEST_URI"], '?');
    header("Location: $currentPage");
    exit;
}
$lang = $_SESSION['lang'] ?? 'en';

$message = "";

if(isset($_POST['reset'])){

    if(!isset($_SESSION['reset_user'])){
        die(t("Unauthorized access"));
    }

    $password = $_POST['password'];
    $confirm  = $_POST['confirm'];

    if($password != $confirm){
        $message = t("Password does not match!");
    } else {

        $hash = password_hash($password, PASSWORD_BCRYPT);
        $username = $_SESSION['reset_user'];

        $sql = "UPDATE users SET password=? WHERE username=?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $hash, $username);

        if($stmt->execute()){
            $message = t("Password updated successfully!");
            session_destroy();
        } else {
            $message = t("Something went wrong!");
        }
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

    <title><?php echo t("Reset Password");?></title>

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
                EN
            </a>
            <a href="?lang=vi" class="lang-btn <?php echo $lang=='vi' ? 'active' : ''; ?>">
                <img src="https://flagcdn.com/w40/vn.png" class="flag-img" alt="Vietnamese">
                VI
            </a>
        </div>

        <div class="form-box">

            <h2 class="text-center mb-4"><?php echo t("Reset Password");?></h2>

            <?php if($message): ?>
            <div class="alert alert-info">
                <?php echo htmlspecialchars($message); ?>
            </div>
            <?php endif; ?>

            <form method="POST">

                <div class="mb-3">
                    <label class="form-label"><?php echo t("New Password");?></label>
                    <input type="password" class="form-control" name="password" required>
                </div>

                <div class="mb-3">
                    <label class="form-label"><?php echo t("Confirm Password");?></label>
                    <input type="password" class="form-control" name="confirm" required>
                </div>

                <div class="d-flex gap-2">
                    <button name="reset" class="btn btn-primary w-50">
                        <i class="bi bi-key"></i> <?php echo t("Reset password");?>
                    </button>

                    <a href="login.php" class="btn btn-secondary w-50">
                        <?php echo t("← Back");?>
                    </a>
                </div>

            </form>

        </div>

    </div>

</body>

</html>
