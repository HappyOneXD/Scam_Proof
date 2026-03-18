<?php
session_start();
require '../Database/database.php';

$message = "";

if(isset($_POST['reset'])){

    if(!isset($_SESSION['reset_user'])){
        die("Unauthorized access");
    }

    $password = $_POST['password'];
    $confirm  = $_POST['confirm'];

    if($password != $confirm){
        $message = "Password does not match!";
    } else {

        $hash = password_hash($password, PASSWORD_BCRYPT);
        $username = $_SESSION['reset_user'];

        $sql = "UPDATE users SET password=? WHERE username=?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $hash, $username);

        if($stmt->execute()){
            $message = "Password updated successfully!";
            session_destroy();
        } else {
            $message = "Something went wrong!";
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

    <title>Reset Password</title>

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

            <h2 class="text-center mb-4">Reset Password</h2>

            <?php if($message): ?>
            <div class="alert alert-info">
                <?php echo htmlspecialchars($message); ?>
            </div>
            <?php endif; ?>

            <form method="POST">

                <div class="mb-3">
                    <label class="form-label">New Password</label>
                    <input type="password" class="form-control" name="password" required>
                </div>

                <div class="mb-3">
                    <label class="form-label">Confirm Password</label>
                    <input type="password" class="form-control" name="confirm" required>
                </div>

                <div class="d-flex gap-2">
                    <button name="reset" class="btn btn-primary w-50">
                        <i class="bi bi-key"></i> Reset password
                    </button>

                    <a href="login.php" class="btn btn-secondary w-50">
                        Back
                    </a>
                </div>

            </form>

        </div>

    </div>

</body>

</html>