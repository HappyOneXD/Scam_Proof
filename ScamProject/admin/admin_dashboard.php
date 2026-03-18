<?php
session_start();
require_once "../../Database/database.php";

/* =========================
ADMIN CHECK
========================= */

if(!isset($_SESSION['role']) || $_SESSION['role'] != 'Admin'){
header("Location: ../index.php");
exit;
}

/* =========================
TOTAL USERS
========================= */

$user_query = $conn->query("SELECT COUNT(*) as total FROM users");
$total_users = $user_query->fetch_assoc()['total'];

/* =========================
DATE FILTER
========================= */

$start = $_GET['start'] ?? date("Y-m-01");
$end = $_GET['end'] ?? date("Y-m-d");

/* =========================
TOTAL SEARCHES
========================= */

$stmt = $conn->prepare("
SELECT COUNT(*) as total
FROM search_history
WHERE DATE(searched_at) BETWEEN ? AND ?
");

$stmt->bind_param("ss",$start,$end);
$stmt->execute();

$result=$stmt->get_result();
$total_search = $result->fetch_assoc()['total'];

/* =========================
TOTAL REPORTS (ACCEPTED)
========================= */

$report_query = $conn->query("
SELECT COUNT(*) as total 
FROM reports 
WHERE status='Accepted'
");

$total_reports = $report_query->fetch_assoc()['total'];

/* =========================
TOTAL SCAM NUMBERS
========================= */

$scam_query = $conn->query("
SELECT COUNT(*) as total
FROM phonenumbers
WHERE type='Scam'
");

$total_scam = $scam_query->fetch_assoc()['total'];

/* =========================
TOP SCAM NUMBERS
========================= */

$month = date("m");
$year = date("Y");

$stmt = $conn->prepare("
SELECT phone, COUNT(*) as total
FROM reports
WHERE status='Accepted'
AND MONTH(created_at)=?
AND YEAR(created_at)=?
GROUP BY phone
ORDER BY total DESC
LIMIT 5
");

$stmt->bind_param("ii",$month,$year);
$stmt->execute();

$result = $stmt->get_result();

$phones = [];
$counts = [];

while($row = $result->fetch_assoc()){

$phones[] = $row['phone'];
$counts[] = $row['total'];

}

if(empty($phones)){
$phones = ["No Data"];
$counts = [0];
}
?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <title>Admin Dashboard</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
    body {
        background: #f4f6f9;
        font-family: Arial;
    }

    /* SIDEBAR */

    .sidebar {
        position: fixed;
        width: 250px;
        height: 100vh;
        background: #1f2d3d;
        color: white;
        transition: 0.3s;
    }

    .sidebar.collapsed {
        width: 70px;
    }

    .sidebar h4 {
        padding: 20px;
        font-size: 30px;
        font-weight: 700;
        letter-spacing: 1px;
    }

    .sidebar a {
        display: flex;
        align-items: center;
        padding: 12px 20px;
        color: #c2c7d0;
        text-decoration: none;
        gap: 10px;
    }

    .sidebar a:hover {
        background: #2c3b4a;
        color: white;
    }

    .sidebar.collapsed h4,
    .sidebar.collapsed span,
    .sidebar.collapsed p {
        display: none;
    }

    .sidebar.collapsed a {
        justify-content: center;
    }

    /* TOPBAR */

    .topbar {
        position: fixed;
        top: 0;
        right: 0;
        left: 250px;
        height: 60px;
        background: #343a40;
        color: white;
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0 20px;
        transition: 0.3s;
        z-index: 1000;
    }

    .topbar.expanded {
        left: 70px;
    }

    /* CONTENT */

    .content {
        margin-left: 250px;
        padding: 90px 30px;
        transition: 0.3s;
    }

    .content.expanded {
        margin-left: 70px;
    }

    .card {
        border-radius: 10px;
    }
    </style>

</head>

<body>

    <!-- SIDEBAR -->

    <div class="sidebar">

        <h4 class="fw-bold fs-1">
            <strong><i class="bi bi-shield-lock fs-1"></i> SCAM SYSTEM</strong>
        </h4>

        <p class="px-3 text-secondary">OVERVIEW</p>

        <a href="admin_dashboard.php">
            <i class="bi bi-speedometer2"></i>
            <span>Dashboard</span>
        </a>

        <p class="px-3 text-secondary mt-3">MANAGEMENT</p>

        <a href="manage_users.php">
            <i class="bi bi-people"></i>
            <span>All Users</span>
        </a>

        <a href="manage_numbers.php">
            <i class="bi bi-telephone"></i>
            <span>Phone Numbers</span>
        </a>

        <a href="manage_reports.php">
            <i class="bi bi-exclamation-triangle"></i>
            <span>Reported Numbers</span>
        </a>

        <p class="px-3 text-secondary mt-3">SYSTEM</p>

        <a href="manage_activity_logs.php">
            <i class="bi bi-activity"></i>
            <span>Activity Logs</span>
        </a>

        <a href="../index.php">
            <i class="bi bi-box-arrow-left"></i>
            <span>Logout</span>
        </a>

    </div>


    <!-- TOPBAR -->

    <div class="topbar">

        <button class="btn btn-dark" onclick="toggleSidebar()">
            <i class="bi bi-list"></i>
        </button>

        <div class="d-flex align-items-center gap-3">

            <form action="search.php" method="GET" class="d-flex">
                <input class="form-control me-2" name="keyword" style="width:300px;" placeholder="Search">
                <button class="btn btn-primary">
                    <i class="bi bi-search"></i>
                </button>
            </form>

            <div class="d-flex align-items-center">
                <i class="bi bi-person-circle fs-4 me-2"></i>

                <?php if($_SESSION['role']=="Admin"){ ?>
                <span>
                    Admin | <?php echo $_SESSION['user_name']; ?>
                </span>
                <?php } ?>

            </div>

        </div>

    </div>

    <!-- CONTENT -->

    <div class="content">

        <h1 class="mb-4">Admin Dashboard</h1>

        <div class="row g-4">

            <div class="col-md-3">
                <div class="card p-3">
                    <h5>Total Users</h5>
                    <h2><?php echo $total_users ?></h2>
                </div>
            </div>

            <div class="col-md-3">
                <div class="card p-3">
                    <h5>Total Searches</h5>
                    <h2><?php echo $total_search ?></h2>
                </div>
            </div>

            <div class="col-md-3">
                <div class="card p-3">
                    <h5>Total Reports</h5>
                    <h2><?php echo $total_reports ?></h2>
                </div>
            </div>

            <div class="col-md-3">
                <div class="card p-3">
                    <h5>Total Scam Numbers</h5>
                    <h2><?php echo $total_scam ?></h2>
                </div>
            </div>

        </div>

        <!-- FILTER -->

        <div class="card mt-4 p-3">

            <form method="GET" class="row g-3">

                <div class="col-md-4">
                    <label>Start Date</label>
                    <input type="date" name="start" class="form-control" value="<?php echo $start ?>">
                </div>

                <div class="col-md-4">
                    <label>End Date</label>
                    <input type="date" name="end" class="form-control" value="<?php echo $end ?>">
                </div>

                <div class="col-md-4 d-flex align-items-end">
                    <button class="btn btn-primary w-100">Filter</button>
                </div>

            </form>

        </div>

        <!-- CHART -->

        <div class="card mt-5 p-4">

            <h5>Top 5 Scam Numbers This Month</h5>

            <canvas id="scamChart"></canvas>

        </div>

    </div>
</body>

</html>

<script>
function toggleSidebar() {

    let sidebar = document.querySelector(".sidebar");
    let content = document.querySelector(".content");
    let topbar = document.querySelector(".topbar");

    sidebar.classList.toggle("collapsed");
    content.classList.toggle("expanded");
    topbar.classList.toggle("expanded");

}

const ctx = document.getElementById('scamChart');

new Chart(ctx, {

    type: 'bar',

    data: {
        labels: <?php echo json_encode($phones); ?>,
        datasets: [{
            label: 'Reports',
            data: <?php echo json_encode($counts); ?>,
            borderWidth: 1
        }]
    }

});
</script>