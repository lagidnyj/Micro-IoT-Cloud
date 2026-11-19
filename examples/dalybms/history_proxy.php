<?php
// Проксі до backend/history.php хмари. Токен береться з read_config.json і не потрапляє в браузер.
// Файл read_config.json шукається поруч або в батьківській теці (де лежить захищений .htaccess панелі).
header('Cache-Control: no-store');

function fail(int $code, string $msg): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    header('Allow: GET');
    fail(405, 'Method not allowed. Use GET.');
}

$device = $_GET['device'] ?? '';
if (!is_string($device) || !preg_match('/\A[a-zA-Z0-9_-]{1,64}\z/', $device)) {
    fail(400, 'Invalid device ID.');
}

$config = null;
foreach ([__DIR__ . '/read_config.json', dirname(__DIR__) . '/read_config.json'] as $p) {
    if (is_file($p)) { $config = json_decode(file_get_contents($p), true); break; }
}
if (!is_array($config) || !is_string($config['read_token'] ?? null) || $config['read_token'] === ''
    || $config['read_token'] === 'REPLACE_WITH_READ_TOKEN' || !is_string($config['read_url'] ?? null)) {
    fail(500, 'Configure read_url and read_token in read_config.json.');
}

// history_url можна задати явно, інакше read.php -> history.php
$base = is_string($config['history_url'] ?? null)
    ? $config['history_url']
    : preg_replace('~/read\.php$~', '/history.php', $config['read_url']);

$u = parse_url($base);
if (filter_var($base, FILTER_VALIDATE_URL) === false || ($u['scheme'] ?? '') !== 'https' || empty($u['host'])
    || isset($u['user']) || isset($u['pass']) || isset($u['query']) || isset($u['fragment'])
    || substr($u['path'] ?? '', -12) !== '/history.php') {
    fail(500, 'history_url must be an HTTPS .../history.php endpoint without query parameters.');
}
if (!function_exists('curl_init')) fail(500, 'PHP cURL extension is required.');

$curl = curl_init($base . '?' . http_build_query(['api_token' => $config['read_token'], 'device' => $device]));
curl_setopt_array($curl, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CONNECTTIMEOUT => 5,
    CURLOPT_TIMEOUT => 30,
    CURLOPT_HTTPHEADER => ['Accept: application/x-ndjson, application/json'],
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
]);
$body = curl_exec($curl);
$err  = curl_errno($curl);
$code = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
curl_close($curl);

if ($body === false || $err !== 0) fail(502, 'Could not connect to the cloud history API.');
if ($code < 200 || $code >= 300) {
    http_response_code($code >= 100 && $code <= 599 ? $code : 502);
    header('Content-Type: application/json; charset=utf-8');
    echo $body;
    exit;
}

header('Content-Type: application/x-ndjson; charset=utf-8');
echo $body;
