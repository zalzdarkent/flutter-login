<?php
include('./config.php');
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $email = $_POST['email'];
    $password = $_POST['password'];

    $sql = "SELECT * FROM user WHERE email = ?";
    $stmt = $koneksi->prepare($sql);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        
        if (password_verify($password, $user['password'])) {
            $auth_token = bin2hex(random_bytes(16)); 

            $update_token_sql = "UPDATE user SET auth_token = ? WHERE email = ?";
            $update_stmt = $koneksi->prepare($update_token_sql);
            $update_stmt->bind_param("ss", $auth_token, $email);
            $update_stmt->execute();

            echo json_encode([
                "status" => "success",
                "message" => "Login berhasil",
                "auth_token" => $auth_token
            ]);
        } else {
            echo json_encode([
                "status" => "error",
                "message" => "Password salah"
            ]);
        }
    } else {
        echo json_encode([
            "status" => "error",
            "message" => "Email tidak ditemukan"
        ]);
    }

    $stmt->close();
}

$koneksi->close();

?>