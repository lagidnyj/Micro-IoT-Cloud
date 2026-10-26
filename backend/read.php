<?php
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

function respond(int $statusCode, array $body): void
{
    http_response_code($statusCode);
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
    header('Allow: GET');
    respond(405, ['error' => 'Method not allowed. Use GET.']);
}

$apiToken = $_GET['api_token'] ?? null;
if (!is_string($apiToken) || $apiToken === '' || strlen($apiToken) > 256) {
    respond(403, ['error' => 'Forbidden. Invalid API token.']);
}

try {
    require __DIR__ . '/../config/db.php';

    $statement = $pdo->prepare('SELECT id FROM users WHERE api_token = :api_token LIMIT 1');
    $statement->execute([':api_token' => $apiToken]);
    $userId = $statement->fetchColumn();

    if ($userId === false) {
        respond(403, ['error' => 'Forbidden. Invalid API token.']);
    }

    $statement = $pdo->prepare(
        'SELECT d.id, d.name, d.last_update, ud.permission '
        . 'FROM user_devices AS ud '
        . 'INNER JOIN devices AS d ON d.id = ud.device_id '
        . 'WHERE ud.user_id = :user_id '
        . 'ORDER BY d.id'
    );
    $statement->execute([':user_id' => (int) $userId]);
    $devices = $statement->fetchAll(PDO::FETCH_ASSOC);

    $storageDir = dirname(__DIR__) . '/storage/';
    $result = [];
    $latestFileModified = null;

    foreach ($devices as $device) {
        $deviceId = $device['id'];
        if (!is_string($deviceId) || !preg_match('/\A[a-zA-Z0-9_-]{1,64}\z/', $deviceId)) {
            error_log('Invalid device ID stored in database.');
            respond(500, ['error' => 'Invalid device configuration.']);
        }

        $filePath = $storageDir . $deviceId . '.json';
        $state = null;
        $fileModified = null;
        if (is_file($filePath)) {
            $fileContents = file_get_contents($filePath);
            if ($fileContents === false) {
                error_log('Could not read device state file: ' . $filePath);
                respond(500, ['error' => 'Could not read device state.']);
            }

            $state = json_decode($fileContents);
            if (json_last_error() !== JSON_ERROR_NONE || !is_object($state)) {
                error_log('Invalid JSON in device state file: ' . $filePath);
                respond(500, ['error' => 'Device state contains invalid JSON.']);
            }

            $fileModified = filemtime($filePath);
            if ($fileModified !== false && ($latestFileModified === null || $fileModified > $latestFileModified)) {
                $latestFileModified = $fileModified;
            }
        }

        $result[$deviceId] = [
            'device_id' => $deviceId,
            'name' => $device['name'],
            'permission' => $device['permission'],
            'last_update' => $device['last_update'],
            'file_modified_unix' => $fileModified === false ? null : $fileModified,
            'state' => $state,
        ];
    }

    if ($latestFileModified !== null) {
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $latestFileModified) . ' GMT');
        header('X-File-Modified-At: ' . gmdate('c', $latestFileModified));
        header('X-File-Modified-Unix: ' . $latestFileModified);
    }

    $responseBody = json_encode((object) $result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($responseBody === false) {
        error_log('Could not encode device read API response: ' . json_last_error_msg());
        respond(500, ['error' => 'Could not encode device data.']);
    }

    echo $responseBody;
} catch (PDOException $error) {
    error_log('Device read API database operation failed: ' . $error->getMessage());
    respond(500, ['error' => 'Database operation failed.']);
}
