<?php
session_start();
require_once '../Database/database.php';

if(!isset($_SESSION['user_id'])){
header("Location: login.php");
exit;
}

$user_id = $_SESSION['user_id'];
$search = $_GET['search'] ?? '';

if($search != ""){

$like = "%$search%";

$stmt = $conn->prepare("SELECT * FROM search_history 
WHERE user_id = ? AND (phonenumber LIKE ? OR searched_at LIKE ?) 
ORDER BY searched_at DESC");

$stmt->bind_param("iss",$user_id,$like,$like);

}else{

$stmt = $conn->prepare("SELECT * FROM search_history 
WHERE user_id=? ORDER BY searched_at DESC");

$stmt->bind_param("i",$user_id);

}

$stmt->execute();
$result = $stmt->get_result();
?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap" rel="stylesheet">

    <title>Search History</title>

    <style>
    body {
        background-image: url("img/background.png");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
        font-family: 'Inter', sans-serif;
    }

    .overlay {
        background: rgba(0, 0, 0, 0.55);
        min-height: 100vh;
        padding-top: 120px;
        padding-bottom: 40px;
        color: white;
    }

    .navbar {
        background: rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(6px);
    }

    .history-card {
        background: white;
        border-radius: 10px;
        padding: 30px;
        box-shadow: 0 5px 20px rgba(0, 0, 0, 0.1);
    }

    .status-safe {
        color: #16a34a;
        font-weight: bold;
    }

    .status-scam {
        color: #dc2626;
        font-weight: bold;
    }

    .status-unknown {
        color: #eab308;
        font-weight: bold;
    }

    .highlight-row {
        background-color: #fff3cd;
        font-weight: 600;
    }

    .footer-custom {
        background: rgba(0, 0, 0, 0.75);
        color: white;
    }

    .footer-link {
        color: #ddd;
        text-decoration: none;
    }

    .footer-link:hover {
        color: white;
        text-decoration: underline;
    }
    </style>

</head>

<body class="d-flex flex-column min-vh-100">

    <nav class="navbar navbar-expand-lg navbar-dark w-100 fixed-top shadow-sm">
        <div class="container-fluid">

            <a class="navbar-brand fw-bold fs-3 me-5" href="index.php">SCAM BTEC</a>

            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarNav">

                <!-- Menu trái -->
                <ul class="navbar-nav me-auto mb-2 mb-lg-0 mx-4 gap-5 fs-6">
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="index.php">HOME</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="phonenumber.php">PHONE NUMBER</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="#">URL</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" aria-current="page" href="#">EMAIL</a>
                    </li>
                </ul>

                <!-- Menu phải (User) -->
                <div class="d-flex align-items-center gap-3">

                    <?php if (isset($_SESSION['user_id'])): ?>

                    <!-- Dropdown User -->
                    <div class="dropdown">
                        <a class="d-flex align-items-center text-white text-decoration-none dropdown-toggle" href="#"
                            role="button" data-bs-toggle="dropdown" aria-expanded="false">

                            <i class="bi bi-person-circle fs-3"></i>
                        </a>

                        <ul class="dropdown-menu dropdown-menu-end shadow">

                            <li class="dropdown-header">
                                <a href="profile.php" class="text-decoration-none text-dark">
                                    <?php echo htmlspecialchars($_SESSION['user_name']); ?>
                                </a>
                            </li>

                            <li>
                                <a class="dropdown-item" href="history.php">
                                    <i class="bi bi-clock-history me-2"></i>
                                    History
                                </a>
                            </li>

                            <li>
                                <hr class="dropdown-divider">
                            </li>

                            <li>
                                <a class="dropdown-item text-danger" href="logout.php">
                                    <i class="bi bi-box-arrow-right me-2"></i>
                                    Logout
                                </a>
                            </li>

                        </ul>
                    </div>

                    <?php else: ?>

                    <a href="login.php" class="btn btn-outline-info">
                        Sign in
                    </a>

                    <a href="register.php" class="btn btn-outline-info">
                        Sign up
                    </a>

                    <?php endif; ?>

                </div>
            </div>
        </div>
    </nav>

    <div class="overlay">

        <div class="container">

            <!-- TITLE + SEARCH -->

            <div class="d-flex justify-content-between align-items-center mb-3">

                <h1 class="text-white">Phone Search History</h1>

                <form class="d-flex" method="GET" action="history.php">

                    <div class="input-group" style="width:350px">

                        <span class="input-group-text">
                            <i class="bi bi-search"></i>
                        </span>

                        <input class="form-control" type="text" name="search" placeholder="Search phone or date"
                            value="<?php echo $_GET['search'] ?? ''; ?>">

                        <button class="btn btn-success" type="submit">
                            Search
                        </button>

                    </div>

                </form>

            </div>


            <!-- TABLE -->

            <div class="history-card">

                <table class="table table-hover">

                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Phone Number</th>
                            <th>Result</th>
                            <th>Date</th>
                        </tr>
                    </thead>

                    <tbody>

                        <?php
                            $i=1;

                            while($row = $result->fetch_assoc()){

                            $highlight="";

                            if($search!="" && 
                            (
                            strpos($row['phonenumber'],$search)!==false ||
                            strpos($row['searched_at'],$search)!==false
                            )){
                            $highlight="highlight-row";
                            }
                        ?>

                        <tr class="<?php echo $highlight; ?>">

                            <td><?php echo $i++; ?></td>

                            <td>
                                <a href="result.php?phone=<?php echo $row['phonenumber']; ?>">
                                    <?php echo $row['phonenumber']; ?>
                                </a>
                            </td>

                            <td>

                                <?php
                                    $type=$row['result_type'];

                                    if($type=="Legitimate"){
                                    echo "<span class='status-safe'>Legitimate</span>";
                                    }
                                    elseif($type=="Scam"){
                                    echo "<span class='status-scam'>Scam</span>";
                                    }
                                    else{
                                    echo "<span class='status-unknown'>Unknown</span>";
                                    }
                                ?>

                            </td>

                            <td><?php echo $row['searched_at']; ?></td>

                        </tr>

                        <?php } ?>

                    </tbody>

                </table>

            </div>


            <!-- BACK BUTTON -->

            <div class="text-end mt-3">

                <a href="index.php" class="btn btn-secondary">
                    <i class="bi bi-arrow-left"></i> Back
                </a>

            </div>

        </div>

    </div>

    <footer class="py-3 border-top footer-custom mt-auto">

        <div class="container">

            <div class="d-flex justify-content-between align-items-center small">

                <div>
                    © 2026 Scam Detection Platform – BTEC FPT
                </div>

                <div>
                    <a href="#" class="footer-link">Privacy Policy</a>
                    &middot;
                    <a href="#" class="footer-link">Terms & Conditions</a>
                </div>

            </div>

        </div>

    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>

</body>

</html>