<?php
session_start();
require_once '../../Database/database.php';

/* CHECK ADMIN LOGIN */

if(!isset($_SESSION['role']) || $_SESSION['role'] != "Admin"){
    header("Location: ../index.php");
    exit;
}

$action = $_GET['action'] ?? 'list';


/* DELETE NUMBER */

if($action == "delete"){

$id = intval($_GET['id']);

mysqli_query($conn,"DELETE FROM phonenumbers WHERE id='$id'");

header("Location: manage_numbers.php");
exit;

}


/* ADD NUMBER */

if(isset($_POST['add_number'])){

$phonenumber = $_POST['phonenumber'];
$type = $_POST['type'];
$country = $_POST['country'];
$description = $_POST['description'];

mysqli_query($conn,"INSERT INTO phonenumbers(phonenumber,type,country,description)
VALUES('$phonenumber','$type','$country','$description')");

header("Location: manage_numbers.php");
exit;

}


/* UPDATE NUMBER */

if(isset($_POST['update_number'])){

$id = $_POST['id'];

$phonenumber = $_POST['phonenumber'];
$type = $_POST['type'];
$country = $_POST['country'];
$description = $_POST['description'];

mysqli_query($conn,"UPDATE phonenumbers
SET phonenumber='$phonenumber',
type='$type',
country='$country',
description='$description'
WHERE id='$id'");

header("Location: manage_numbers.php");
exit;

}

/* SEARCH */

$keyword = $_GET['keyword'] ?? '';
$keyword = mysqli_real_escape_string($conn,$keyword);

if($keyword!=""){

$sql="SELECT * FROM phonenumbers
WHERE phonenumber LIKE '%$keyword%'
ORDER BY created_at DESC";

}else{

$sql="SELECT * FROM phonenumbers
ORDER BY created_at DESC";

}

$result=mysqli_query($conn,$sql);

?>

<!DOCTYPE html>
<html>

<head>

    <title>Phone Number Management</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" rel="stylesheet">

    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
        color: #e4e9f4;
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

            <?php if($action == "list"){ ?>

            <h1>Phone Number Management</h1>

            <?php } ?>

            <?php

/* ======================
ADD NUMBER
====================== */

if($action == "add"){
?>

            <h4>Add Phone Number</h4>

            <form method="POST">

                <label class="mt-3">Phone Number</label>
                <input type="text" name="phonenumber" class="form-control" required>

                <label class="mt-3">Type</label>
                <select name="type" class="form-control">
                    <option>Legitimate</option>
                    <option>Scam</option>
                    <option>Unknown</option>
                </select>

                <label class="mt-3">Country</label>
                <input type="text" name="country" class="form-control">

                <label class="mt-3">Description</label>
                <textarea name="description" class="form-control"></textarea>

                <div class="mt-4 d-flex justify-content-between">

                    <button class="btn btn-success" name="add_number">
                        Create
                    </button>

                    <a href="manage_numbers.php" class="btn btn-secondary">
                        Back
                    </a>

                </div>

            </form>

            <?php
}


/* ======================
EDIT NUMBER
====================== */

elseif($action == "edit"){

$id = $_GET['id'];

$number = mysqli_fetch_assoc(
mysqli_query($conn,"SELECT * FROM phonenumbers WHERE id='$id'")
);

?>

            <h4>Edit Phone Number</h4>

            <form method="POST">

                <input type="hidden" name="id" value="<?php echo $number['id'] ?>">

                <label>Phone Number</label>
                <input type="text" name="phonenumber" value="<?php echo $number['phonenumber'] ?>" class="form-control">

                <label class="mt-3">Type</label>

                <select name="type" class="form-control">

                    <option <?php if($number['type']=="Legitimate") echo "selected"; ?>>Legitimate</option>
                    <option <?php if($number['type']=="Scam") echo "selected"; ?>>Scam</option>
                    <option <?php if($number['type']=="Unknown") echo "selected"; ?>>Unknown</option>

                </select>

                <label class="mt-3">Country</label>
                <input type="text" name="country" value="<?php echo $number['country'] ?>" class="form-control">

                <label class="mt-3">Description</label>
                <textarea name="description" class="form-control"><?php echo $number['description'] ?></textarea>

                <button class="btn btn-primary mt-4" name="update_number">
                    Update
                </button>

                <a href="manage_numbers.php" class="btn btn-secondary mt-4">
                    Back
                </a>

            </form>

            <?php
}


/* ======================
NUMBER LIST
====================== */

else{

$keyword="";

if($keyword!=""){

$keyword=$_GET['keyword'];

$sql="SELECT * FROM phonenumbers
WHERE phonenumber LIKE '%$keyword%'
ORDER BY created_at DESC";

}else{

$sql="SELECT * FROM phonenumbers
ORDER BY created_at DESC";

}

$result=mysqli_query($conn,$sql);

?>

                <div class="d-flex align-items-center justify-content-between mt-4 mb-3">

                <form method="GET" class="d-flex" style="max-width:400px; width:100%;">

                    <input type="text" name="keyword" class="form-control me-3" placeholder="Search phone number..."
                        value="<?php echo $keyword ?>">

                    <button class="btn btn-primary me-2">
                        <i class="bi bi-search"></i>
                    </button>

                    <a href="manage_numbers.php" class="btn btn-secondary">
                        Reset
                    </a>

                </form>

                <a href="manage_numbers.php?action=add" class="btn btn-success">
                    Add Phone Number
                </a>

            </div>


            <table class="table table-bordered table-striped mt-4">

                <thead class="table-dark">

                    <tr>

                        <th>ID</th>
                        <th>Phone Number</th>
                        <th>Type</th>
                        <th>Country</th>
                        <th>Description</th>
                        <th>Reports</th>
                        <th>Created</th>
                        <th>Action</th>

                    </tr>

                </thead>

                <tbody>

                    <?php while($row=mysqli_fetch_assoc($result)){ 

$rowClass = "";

if($row['report_count'] >= 5){
$rowClass = "table-danger";
}
elseif($row['report_count'] >= 3){
$rowClass = "table-warning";
}
elseif($row['report_count'] > 0){
$rowClass = "table-info";
}

?>
<tr class="<?php echo $rowClass; ?>">

                    <tr>

                        <td><?php echo $row['id'] ?></td>

                        <td><?php echo $row['phonenumber'] ?></td>

                        <td>

                            <?php

                                if($row['type']=="Scam"){
                                echo "<span class='text-danger fw-bold'>Scam</span>";
                                }

                                elseif($row['type']=="Legitimate"){
                                echo "<span class='text-success fw-bold'>Legitimate</span>";
                                }

                                else{
                                echo "<span class='text-secondary'>Unknown</span>";
                                }

                            ?>

                        </td>

                        <td><?php echo $row['country'] ?></td>

                        <td><?php echo $row['description'] ?></td>

                        <td><?php echo $row['report_count'] ?></td>

                        <td><?php echo $row['created_at'] ?></td>

                        <td>

                            <a href="manage_numbers.php?action=edit&id=<?php echo $row['id'] ?>"
                                class="btn btn-warning btn-sm">
                                Edit
                            </a>

                            <a href="manage_numbers.php?action=delete&id=<?php echo $row['id'] ?>"
                                class="btn btn-danger btn-sm" onclick="return confirm('Delete this number?')">
                                Delete
                            </a>

                        </td>

                    </tr>

                    <?php } ?>

                </tbody>

            </table>

            <a href="admin_dashboard.php" class="btn btn-secondary">
                Back
            </a>

            <?php } ?>

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