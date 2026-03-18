<?php
session_start();
require_once '../../Database/database.php';

/* CHECK ADMIN LOGIN */

if(!isset($_SESSION['role']) || $_SESSION['role'] != "Admin"){
    header("Location: ../index.php");
    exit;
}

$action = $_GET['action'] ?? 'list';


/* DELETE USER */

if($action == "delete"){

$id = intval($_GET['id']);

mysqli_query($conn,"DELETE FROM users WHERE id='$id'");

header("Location: manage_users.php");
exit;

}


/* ADD USER */

if(isset($_POST['add_user'])){

$username = $_POST['username'];
$password = password_hash($_POST['password'], PASSWORD_BCRYPT);
$role = $_POST['role'];

mysqli_query($conn,"INSERT INTO users(username,password,role,status)
VALUES('$username','$password','$role','Inactive')");

header("Location: manage_users.php");
exit;

}


/* UPDATE USER */

if(isset($_POST['update_user'])){

$id = $_POST['id'];

$username = $_POST['username'];
$role = $_POST['role'];
$status = $_POST['status'];

mysqli_query($conn,"UPDATE users
SET username='$username',
role='$role'
WHERE id='$id'");

header("Location: manage_users.php");
exit;

}
?>

<!DOCTYPE html>
<html>

<head>

    <title>User Management</title>
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

            <h1>User Management</h1>

            <?php } ?>

            <?php

/* ======================
ADD USER FORM
====================== */

if($action == "add"){
?>

            <h2>Add User</h2>

            <form method="POST" class="container mt-1 ">

                <label class="mt-3">Username</label>
                <input type="text" name="username" class="form-control" required>

                <label class="mt-3">Password</label>
                <input type="password" name="password" class="form-control" required>

                <label class="mt-3">Role</label>
                <select name="role" class="form-control">
                    <option>User</option>
                    <option>Admin</option>
                    <option>Employee</option>
                </select>

                <div class="d-flex justify-content-between mt-4">

                    <button class="btn btn-success" name="add_user">
                        Create
                    </button>

                    <a href="manage_users.php" class="btn btn-secondary">
                        Back
                    </a>

                </div>

            </form>

            <?php
}

/* ======================
EDIT USER
====================== */

elseif($action == "edit"){

$id = $_GET['id'];

$user = mysqli_fetch_assoc(
mysqli_query($conn,"SELECT * FROM users WHERE id='$id'")
);

?>

            <h4>Edit User</h4>

            <form method="POST">

                <input type="hidden" name="id" value="<?php echo $user['id'] ?>">

                <label>Username</label>
                <input type="text" name="username" value="<?php echo $user['username'] ?>" class="form-control">

                <label class="mt-2">Role</label>
                <select name="role" class="form-control">
                    <option>User</option>
                    <option>Admin</option>
                    <option>Employee</option>
                </select>

                <button class="btn btn-primary mt-3" name="update_user">
                    Update
                </button>

                <a href="manage_users.php" class="btn btn-secondary mt-3">
                    Back
                </a>

            </form>

            <?php
}

/* ======================
USER LIST
====================== */

else{

$keyword="";

if(isset($_GET['keyword'])){

$keyword=$_GET['keyword'];

$sql="SELECT * FROM users
WHERE username LIKE '%$keyword%'
ORDER BY created_at DESC";

}else{

$sql="SELECT * FROM users
ORDER BY created_at DESC";

}

$result=mysqli_query($conn,$sql);

?>

<div class="d-flex align-items-center justify-content-between mt-4 mb-3">

                <form method="GET" class="d-flex" style="max-width:400px; width:100%;">

                    <input type="text" name="keyword" class="form-control me-3" placeholder="Search user..."
                        value="<?php echo $keyword ?>">

                    <button class="btn btn-primary me-2">
                        <i class="bi bi-search"></i>
                    </button>

                    <a href="manage_users.php" class="btn btn-secondary">
                        Reset
                    </a>

                </form>
            

                <a href="manage_users.php?action=add" class="btn btn-success">
                    Add User
                </a>

            </div>

            <table class="table table-bordered table-striped table-hover mt-4">

                <thead class="table-dark">

                    <tr>

                        <th>ID</th>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Last Login</th>
                        <th>Action</th>

                    </tr>

                </thead>

                <tbody>

                    <?php while($row=mysqli_fetch_assoc($result)){ ?>

                    <tr>

                        <td><?php echo $row['id'] ?></td>

                        <td><?php echo $row['username'] ?></td>

                        <td>

<?php
if($row['role']=="Admin"){
echo "<span class='badge bg-danger'>Admin</span>";
}
elseif($row['role']=="Employee"){
echo "<span class='badge bg-success'>Employee</span>";
}
else{
echo "<span class='badge bg-primary'>User</span>";
}
?>

</td>

                        <td>

                            <?php

if($row['status']=="Active"){
echo "<span class='text-success fw-bold'>Active</span>";
}

elseif($row['status']=="Blocked"){
echo "<span class='text-danger fw-bold'>Blocked</span>";
}

else{
echo "<span class='text-dark'>Inactive</span>";
}

?>

                        </td>

                        <td><?php echo $row['created_at'] ?></td>

                        <td><?php echo $row['last_login'] ?></td>

                        <td>

                            <a href="manage_users.php?action=edit&id=<?php echo $row['id'] ?>" class="btn btn-warning btn-sm">
                                Edit
                            </a>

                            <a href="manage_users.php?action=delete&id=<?php echo $row['id'] ?>" class="btn btn-danger btn-sm"
                                onclick="return confirm('Are you sure you want to delete user: <?php echo $row['username']; ?> ?')">
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