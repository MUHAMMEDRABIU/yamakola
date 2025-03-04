<?php
include '../config.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $phone = trim($_POST['phone'] ?? '');
    $password = trim($_POST['password'] ?? '');
    $confirm_password = trim($_POST['password_confirmation'] ?? '');
    $role = "user"; // Default role

    // Validate required fields
    if (empty($name) || empty($email) || empty($phone) || empty($password) || empty($confirm_password)) {
        die("<script>alert('Error: All fields are required.'); window.history.back();</script>");
    }

    // Validate phone number (only numbers, 11-15 characters)
    if (!preg_match("/^[0-9]{11,15}$/", $phone)) {
        die("<script>alert('Error: Invalid phone number. Enter 11-15 digits.'); window.history.back();</script>");
    }

    // Check if passwords match
    if ($password !== $confirm_password) {
        die("<script>alert('Error: Passwords do not match.'); window.history.back();</script>");
    }

    // Hash password for security
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    // Ensure email is unique
    $checkEmail = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $checkEmail->bind_param("s", $email);
    $checkEmail->execute();
    $checkEmail->store_result();
    
    if ($checkEmail->num_rows > 0) {
        die("<script>alert('Error: Email is already registered.'); window.history.back();</script>");
    }
    $checkEmail->close();

    // Insert user into the database
    $sql = "INSERT INTO users (name, email, phone, password, role) VALUES (?, ?, ?, ?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sssss", $name, $email, $phone, $hashedPassword, $role);

    if ($stmt->execute()) {
        echo "<script>alert('User registered successfully!'); window.location.href='login.php';</script>";
    } else {
        echo "<script>alert('Error registering user: " . addslashes($stmt->error) . "'); window.history.back();</script>";
    }

    $stmt->close();
    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="assets/signup.css">
    <style>
        body{
            background-image: image-set('ii.jpeg');
            background-repeat: no-repeat;
        }
    </style>
</head>
<body class="flex items-center justify-center min-h-screen bg-cover bg-center">

    <div class="w-full max-w-md bg-white p-6 rounded-lg shadow-lg backdrop-blur-md bg-opacity-80">
        <h2 class="text-center text-3xl text-green-700 font-bold mb-4">Create an Account</h2>
        <p class="text-center text-gray-600 mb-6">Sign up to manage your farm efficiently</p>

        <form method="POST" action="Signup.php">
            <div class="mb-4">
                <label class="block text-gray-700 font-medium">Full Name</label>
                <input type="text" name="name" required class="w-full px-4 py-2 border rounded-md focus:ring focus:ring-green-300">
            </div>
            <div class="mb-4">
                <label class="block text-gray-700 font-medium">Email</label>
                <input type="email" name="email" required class="w-full px-4 py-2 border rounded-md focus:ring focus:ring-green-300">
            </div>
            <div class="mb-4">
                <label class="block text-gray-700 font-medium">Phone</label>
                <input type="tel" name="phone" required pattern="[0-9]{11,15}" title="Enter a valid phone number (11-15 digits)" class="w-full px-4 py-2 border rounded-md focus:ring focus:ring-green-300">
            </div>
            <div class="mb-4">
                <label class="block text-gray-700 font-medium">Password</label>
                <input type="password" name="password" required class="w-full px-4 py-2 border rounded-md focus:ring focus:ring-green-300">
            </div>
            <div class="mb-4">
                <label class="block text-gray-700 font-medium">Confirm Password</label>
                <input type="password" name="password_confirmation" required class="w-full px-4 py-2 border rounded-md focus:ring focus:ring-green-300">
            </div>
            <div class="flex items-center justify-between mb-4">
                <a href="login.php" class="text-green-600 text-sm hover:text-green-800">Already registered?</a>
                <button type="submit" class="bg-green-600 text-white px-6 py-2 rounded-md hover:bg-green-700 transition-all">
                    Register
                </button>
            </div>
        </form>
    </div>

</body>
</html>
