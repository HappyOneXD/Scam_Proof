<?php
session_start();
require '../Database/database.php';

$username="";
$password="";
$confirm="";
$dob="";
$gender="";

$username_error="";
$password_error="";
$confirm_error="";
$dob_error="";
$gender_error="";
$success="";

if($_SERVER["REQUEST_METHOD"]=="POST"){

$username = trim($_POST["username"] ?? "");
$password = $_POST["password"] ?? "";
$confirm = $_POST["confirm_password"] ?? "";
$dob = $_POST["dob"] ?? "";
$gender = $_POST["gender"] ?? "";

/* USERNAME VALIDATION */

if(!preg_match('/^[A-Z][a-zA-Z0-9]{7,}$/',$username)){
$username_error="Username must start with a capital letter and be at least 8 characters.";
}

/* PASSWORD VALIDATION */

if(!preg_match('/^(?=.*[A-Z])(?=.*[0-9])(?=.*[\W]).{8,}$/',$password)){
$password_error="Password must be at least 8 characters and contain uppercase, number and special character.";
}

/* CONFIRM PASSWORD */

if($password != $confirm){
$confirm_error="Passwords do not match.";
}

/* DOB VALIDATION */

/* DOB VALIDATION */

if(empty($dob)){
$dob_error="Date of birth is required.";
}elseif($dob > date("Y-m-d")){
$dob_error="Date of birth cannot be in the future.";
}

/* GENDER VALIDATION */

if($gender!="Male" && $gender!="Female"){
$gender_error="Please select gender.";
}

/* CHECK USERNAME EXIST */

if(empty($username_error) && empty($password_error) && empty($confirm_error) && empty($dob_error) && empty($gender_error)){

$sql="SELECT id FROM users WHERE username=?";
$stmt=$conn->prepare($sql);
$stmt->bind_param("s",$username);
$stmt->execute();
$result=$stmt->get_result();

if($result->num_rows>0){

$username_error="Username already exists.";

}else{

$password_hash=password_hash($password,PASSWORD_BCRYPT);

$sql="INSERT INTO users(username,password,dob,gender) VALUES(?,?,?,?)";
$stmt=$conn->prepare($sql);
$stmt->bind_param("ssss",$username,$password_hash,$dob,$gender);

if($stmt->execute()){

$success="Registration successful!";
$username="";
$password="";
$confirm="";
$dob="";
$gender="";

}

}

}

}
?>


<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">

    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">

    <title>Register</title>

    <style>
    body {
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        min-height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 40px 0;
    }

    .overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.6);
        z-index: -1;
    }

    .register-box {
        position: relative;
        width: 100%;
        max-width: 550px;
        /* nhỏ ngang hơn */
        background: rgba(0, 0, 0, 0.6);
        padding: 25px 20px;
        /* giảm chiều cao */
        border-radius: 12px;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.4);
        z-index: 1;
        color: white;
    }

    .register-box h3 {
        font-weight: 700;
    }

    .form-control {
        border-radius: 8px;
    }

    .form-control:focus {
        box-shadow: 0 0 5px rgba(13, 110, 253, .5);
    }

    .error {
        color: red;
        font-size: 13px;
    }

    .strength {
        font-size: 13px;
        margin-top: 3px;
    }

    .btn-primary {
        border-radius: 8px;
        width: 120px;
    }

    .btn-secondary {
        border-radius: 8px;
        width: 120px;
    }

    .links {
        display: flex;
        justify-content: space-between;
        margin-top: 15px;
    }
    </style>

</head>

<body>

    <div class="overlay"></div>

    <div class="register-box">

        <h3 class="text-center mb-4">Register</h3>

        <?php if($success!=""){ ?>
        <div class="alert alert-success text-center">
            <?php echo $success ?>
        </div>
        <?php } ?>

        <form method="POST">

            <div class="mb-3">

                <label class="form-label">Username</label>

                <input type="text" class="form-control" name="username" placeholder="Enter username"
                    value="<?php echo $username ?>">

                <div class="error"><?php echo $username_error ?></div>

            </div>

            <div class="mb-3">

                <label class="form-label">Date of Birth</label>

                <input type="date" class="form-control" name="dob" max="<?php echo date('Y-m-d'); ?>"
                    value="<?php echo htmlspecialchars($dob); ?>">

                <div class="error"><?php echo $dob_error ?></div>

            </div>

            <div class="mb-3">

                <label class="form-label">Gender</label>

                <select class="form-control" name="gender">

                    <option value="">Select Gender</option>

                    <option value="Male" <?php if($gender=="Male") echo "selected"; ?>>Male</option>

                    <option value="Female" <?php if($gender=="Female") echo "selected"; ?>>Female</option>

                </select>

                <div class="error"><?php echo $gender_error ?></div>

            </div>

            <div class="mb-3">

                <label class="form-label">Password</label>

                <div class="input-group">

                    <input type="password" class="form-control" id="password" name="password"
                        placeholder="Enter password" value="<?php echo htmlspecialchars($password); ?>"
                        onkeyup="checkStrength()">

                    <span class="input-group-text" onclick="togglePassword('password',this)">

                        <i class="bi bi-eye"></i>

                    </span>

                </div>

                <div id="strength" class="strength"></div>

                <div class="error"><?php echo $password_error ?></div>

            </div>


            <div class="mb-3">

                <label class="form-label">Confirm Password</label>

                <div class="input-group">

                    <input type="password" class="form-control" id="confirm" name="confirm_password"
                        placeholder="Confirm password" onkeyup="checkStrength()">

                    <span class="input-group-text" onclick="togglePassword('confirm',this)">
                        <i class="bi bi-eye"></i>
                    </span>

                </div>

                <div class="error"><?php echo $confirm_error ?></div>

            </div>

            <div class="d-flex justify-content-between mt-4">

                <button type="submit" class="btn btn-primary">
                    Register
                </button>

                <a href="login.php" class="btn btn-secondary">
                    Back
                </a>

            </div>

            <div class="links">

                <a href="login.php">You already have an account. Login here</a>

            </div>
        </form>

    </div>

    <script>
    function togglePassword(id, icon) {

        let input = document.getElementById(id);
        let i = icon.querySelector("i");

        if (input.type === "password") {
            input.type = "text";
            i.classList.replace("bi-eye", "bi-eye-slash");
        } else {
            input.type = "password";
            i.classList.replace("bi-eye-slash", "bi-eye");
        }

    }

    function checkStrength() {

        let pass = document.getElementById("password").value;
        let strength = document.getElementById("strength");

        let regexWeak = /^(?=.*[A-Z]).{8,}$/;
        let regexMedium = /^(?=.*[A-Z])(?=.*[0-9]).{8,}$/;
        let regexStrong = /^(?=.*[A-Z])(?=.*[0-9])(?=.*[\W]).{8,}$/;

        if (regexStrong.test(pass)) {
            strength.innerHTML = "Strong password";
            strength.style.color = "green";
        } else if (regexMedium.test(pass)) {
            strength.innerHTML = "Medium password";
            strength.style.color = "orange";
        } else if (regexWeak.test(pass)) {
            strength.innerHTML = "Weak password";
            strength.style.color = "red";
        } else {
            strength.innerHTML = "";
        }

    }
    </script>

</body>

</html>