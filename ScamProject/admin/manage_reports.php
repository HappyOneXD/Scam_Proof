<?php
session_start();
require_once '../../Database/database.php';

/* CHECK ADMIN */

if(!isset($_SESSION['role']) || $_SESSION['role']!="Admin"){
header("Location: ../index.php");
exit;
}

/* ACCEPT REPORT */

if(isset($_GET['accept'])){

$id = intval($_GET['accept']);

$result = mysqli_query($conn,"SELECT * FROM reports WHERE id='$id'");
$report = mysqli_fetch_assoc($result);

if(!$report){
header("Location: manage_reports.php");
exit;
}

$phone = $report['phone'];
$desc = $report['report_reason']." - ".$report['comment'];

/* CHECK NUMBER */

$check=mysqli_query($conn,"SELECT * FROM phonenumbers WHERE phonenumber='$phone'");

if(mysqli_num_rows($check)>0){

/* INCREASE REPORT COUNT */

mysqli_query($conn,"
UPDATE phonenumbers
SET 
report_count = report_count + 1,
description = CONCAT(description,' | $desc')
WHERE phonenumber='$phone'
");

/* MARK SCAM IF REPORT >=3 */

mysqli_query($conn,"
UPDATE phonenumbers
SET type='Scam'
WHERE phonenumber='$phone'
AND report_count >= 3
");

}else{

/* INSERT NEW NUMBER */

mysqli_query($conn,"
INSERT INTO phonenumbers
(phonenumber,type,country,description,report_count)
VALUES
('$phone','Unknown','Viet Nam','$desc',1)
");

}

/* DELETE REPORT */

mysqli_query($conn,"DELETE FROM reports WHERE id='$id'");

header("Location: manage_reports.php");
exit;

}


/* REJECT REPORT */

if(isset($_GET['reject'])){

$id = intval($_GET['reject']);

mysqli_query($conn,"DELETE FROM reports WHERE id='$id'");

header("Location: manage_reports.php");
exit;

}


$search = $_GET['search'] ?? '';

$search = mysqli_real_escape_string($conn,$search);

if($search != ''){

$result = mysqli_query($conn,"
SELECT * FROM reports
WHERE phone LIKE '%$search%'
ORDER BY created_at DESC
");

}else{

$result=mysqli_query($conn,"SELECT * FROM reports ORDER BY created_at DESC");

}
?>

<!DOCTYPE html>
<html>

<head>

    <title>Report Management</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" rel="stylesheet">

    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>

    <style>
    body {
        background: #fafcfe;
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
    .sidebar.collapsed p,
    .sidebar.collapsed span {
        display: none;
    }

    .sidebar.collapsed a {
        justify-content: center;
    }

    .sidebar.collapsed i {
        margin-right: 0;
        font-size: 20px;
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
            <strong><i class="bi bi-shield-lock fs-1"></i>  SCAM SYSTEM</strong>
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

    <div class="content">
        <div class="container mt-1">

            <h1>Reported Numbers</h1>

            <div class="d-flex align-items-center justify-content-between mt-4 mb-3">

                <form method="GET" class="d-flex" style="max-width:400px; width:100%;">

                    <input type="text" name="search" class="form-control me-2" placeholder="Search phone number"
                        value="<?php echo $_GET['search'] ?? ''; ?>">

                    <button class="btn btn-primary me-2">
                        <i class="bi bi-search"></i>
                    </button>

                    <a href="manage_reports.php" class="btn btn-secondary">
                        Reset
                    </a>

                </form>

            </div>

            <?php
            $reportCount = [];

$countQuery = mysqli_query($conn,"
SELECT phone, COUNT(*) as total
FROM reports
GROUP BY phone
");

while($rowCount = mysqli_fetch_assoc($countQuery)){
    $reportCount[$rowCount['phone']] = $rowCount['total'];
}
?>
            <table class="table table-bordered table-striped table-hover mt-4">
                <thead class="table-dark">

                    <tr>

                        <th>ID</th>
                        <th>Phone</th>
                        <th>Reported By</th>
                        <th>Reason</th>
                        <th>Comment</th>
                        <th>Reports</th>
                        <th>Date</th>
                        <th>Action</th>

                    </tr>

                </thead>

                <tbody>

                    <?php

$result=mysqli_query($conn,"SELECT * FROM reports ORDER BY created_at DESC");

while($row=mysqli_fetch_assoc($result)){

?>

                    <tr>

                        <td><?php echo $row['id']; ?></td>

                        <td><?php echo $row['phone']; ?></td>

                        <td>
                            <span class="text-secondary">
                                Anonymous
                            </span>
                        </td>

                        <td style="max-width:200px;">
                            <?php echo $row['report_reason']; ?>
                        </td>

                        <td><?php echo $row['comment']; ?></td>
                        <td>
<?php 
$count = $reportCount[$row['phone']] ?? 0;

if($count >= 5){
    echo "<span class='badge bg-danger'>$count - Dangerous</span>";
}
elseif($count >= 3){
    echo "<span class='badge bg-warning'>$count - Scam</span>";
}
elseif($count > 0){
    echo "<span class='badge bg-info'>$count - Suspicious</span>";
}
else{
    echo "<span class='badge bg-secondary'>0</span>";
}
?>
</td>
                        <td><?php echo $row['created_at']; ?></td>

                        <td>

                            <a href="?accept=<?php echo $row['id']; ?>" class="btn btn-success btn-sm"
                                onclick="return confirm('Accept this report?')">

                                <i class="bi bi-check-circle"></i> Accept

                            </a>

                            <a href="?reject=<?php echo $row['id']; ?>" class="btn btn-danger btn-sm"
                                onclick="return confirm('Reject this report?')">

                                <i class="bi bi-x-circle"></i> Reject

                            </a>

                        </td>

                    </tr>

                    <?php } ?>

                </tbody>

            </table>
            <a href="admin_dashboard.php" class="btn btn-secondary">
                Back
            </a>

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
</script>