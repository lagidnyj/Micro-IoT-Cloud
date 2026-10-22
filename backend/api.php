<?php
// Директорія для збереження файлів
$storageDir = dirname(__DIR__) . '/storage/';

if (!is_dir($storageDir)) {
    mkdir($storageDir, 0755, true);
}

// 1. Перевірка методом POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(["error" => "Method not allowed. Use POST."]);
    exit;
}

// 2. Базова токен-авторизація
// Очікуємо заголовок типу: Authorization: Bearer твій_секретний_токен
$headers = getallheaders();
$authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
$expectedToken = 'ТВОЙ_СЕКРЕТНИЙ_КЛЮЧ_ЯКИЙ_ТРЕБА_ЗМІНИТИ'; // Задай свій складний ключ

if ($authHeader !== 'Bearer ' . $expectedToken) {
    http_response_code(401);
    echo json_encode(["error" => "Unauthorized. Invalid or missing token."]);
    exit;
}

// 3. Визначаємо ім'я пристрою
$deviceId = $_GET['device'] ?? $_SERVER['HTTP_X_DEVICE_ID'] ?? 'unknown_device';
$deviceId = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $deviceId);
$filePath = $storageDir . $deviceId . '.json';

// 4. Отримуємо та валідуємо JSON
$inputData = file_get_contents('php://input');

$decoded = json_decode($inputData);
if (json_last_error() !== JSON_ERROR_NONE || !is_object($decoded)) {
    http_response_code(400);
    echo json_encode(["error" => "Expected a JSON object"]);
    exit;
}

// 5. Перезаписуємо файл
if (file_put_contents($filePath, $inputData) === false) {
    http_response_code(500);
    echo json_encode(["error" => "Failed to save file"]);
    exit;
}

http_response_code(200);
echo json_encode([
    "status" => "success",
    "device" => $deviceId,
    "bytes_written" => strlen($inputData)
]);
