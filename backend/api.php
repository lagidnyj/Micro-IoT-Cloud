<?php
header('Content-Type: application/json; charset=utf-8');

function respond(int $statusCode, array $body): void
{
    http_response_code($statusCode);
    echo json_encode($body, JSON_UNESCAPED_UNICODE);
    exit;
}

function requestHeader(string $name): string
{
    if (function_exists('getallheaders')) {
        foreach (getallheaders() as $headerName => $value) {
            if (strcasecmp((string) $headerName, $name) === 0 && is_string($value)) {
                return $value;
            }
        }
    }

    $serverName = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
    $value = $_SERVER[$serverName] ?? '';

    return is_string($value) ? $value : '';
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    respond(405, ['error' => 'Method not allowed. Use POST.']);
}

$inputData = file_get_contents('php://input');
if ($inputData === false) {
    respond(400, ['error' => 'Could not read request body.']);
}

$decoded = json_decode($inputData);
if (json_last_error() !== JSON_ERROR_NONE || !is_object($decoded)) {
    respond(400, ['error' => 'Expected a JSON object.']);
}

$bodyDeviceId = property_exists($decoded, 'device_id') ? $decoded->device_id : null;
if ($bodyDeviceId !== null && !is_string($bodyDeviceId)) {
    respond(400, ['error' => 'Invalid device_id.']);
}

$queryDeviceId = $_GET['device'] ?? null;
$headerDeviceId = requestHeader('X-Device-Id');
$deviceId = $bodyDeviceId
    ?? (is_string($queryDeviceId) && $queryDeviceId !== '' ? $queryDeviceId : null)
    ?? ($headerDeviceId !== '' ? $headerDeviceId : null);

if (!is_string($deviceId) || !preg_match('/\A[a-zA-Z0-9_-]{1,64}\z/', $deviceId)) {
    respond(400, ['error' => 'Missing or invalid device_id.']);
}

$bodyDeviceToken = property_exists($decoded, 'device_token') ? $decoded->device_token : null;
if ($bodyDeviceToken !== null && !is_string($bodyDeviceToken)) {
    respond(403, ['error' => 'Forbidden. Invalid device token.']);
}

$authorization = requestHeader('Authorization');
$headerDeviceToken = '';
if (strncmp($authorization, 'Bearer ', 7) === 0) {
    $headerDeviceToken = substr($authorization, 7);
}

if (is_string($bodyDeviceToken)
    && $headerDeviceToken !== ''
    && !hash_equals($bodyDeviceToken, $headerDeviceToken)
) {
    respond(403, ['error' => 'Forbidden. Invalid device token.']);
}

$deviceToken = is_string($bodyDeviceToken) && $bodyDeviceToken !== ''
    ? $bodyDeviceToken
    : $headerDeviceToken;
if ($deviceToken === '') {
    respond(403, ['error' => 'Forbidden. Missing device token.']);
}

if (property_exists($decoded, 'payload')) {
    if (!is_object($decoded->payload)) {
        respond(400, ['error' => 'Payload must be a JSON object.']);
    }
    $payload = json_encode($decoded->payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
} else {
    $state = clone $decoded;
    unset($state->device_token);
    $payload = property_exists($decoded, 'device_token')
        ? json_encode($state, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
        : $inputData;
}

if ($payload === false) {
    respond(400, ['error' => 'Could not encode device payload.']);
}

try {
    require __DIR__ . '/../config/db.php';

    $statement = $pdo->prepare('SELECT device_token FROM devices WHERE id = :device_id');
    $statement->execute([':device_id' => $deviceId]);
    $storedToken = $statement->fetchColumn();

    if (!is_string($storedToken) || !hash_equals($storedToken, $deviceToken)) {
        respond(403, ['error' => 'Forbidden. Invalid device token.']);
    }

    $storageDir = dirname(__DIR__) . '/storage/';
    if (!is_dir($storageDir) && !mkdir($storageDir, 0755, true) && !is_dir($storageDir)) {
        error_log('Could not create API storage directory: ' . $storageDir);
        respond(500, ['error' => 'Failed to prepare storage.']);
    }

    $filePath = $storageDir . $deviceId . '.json';
    $lastUpdate = date('Y-m-d H:i:s');

    $pdo->beginTransaction();
    $statement = $pdo->prepare(
        'UPDATE devices SET last_payload = :payload, last_update = :last_update '
        . 'WHERE id = :device_id AND device_token = :device_token'
    );
    $statement->execute([
        ':payload' => $payload,
        ':last_update' => $lastUpdate,
        ':device_id' => $deviceId,
        ':device_token' => $deviceToken,
    ]);

    if ($statement->rowCount() !== 1) {
        $pdo->rollBack();
        respond(403, ['error' => 'Forbidden. Invalid device token.']);
    }

    $bytesWritten = file_put_contents($filePath, $payload, LOCK_EX);
    if ($bytesWritten === false) {
        $pdo->rollBack();
        error_log('Could not write device payload: ' . $filePath);
        respond(500, ['error' => 'Failed to save file.']);
    }

    $pdo->commit();
} catch (PDOException $error) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('Device API database operation failed: ' . $error->getMessage());
    respond(500, ['error' => 'Database operation failed.']);
}

respond(200, [
    'status' => 'success',
    'device' => $deviceId,
    'bytes_written' => $bytesWritten,
]);
