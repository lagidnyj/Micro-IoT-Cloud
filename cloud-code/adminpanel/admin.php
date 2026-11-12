<?php
declare(strict_types=1);

ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
    'httponly' => true,
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'samesite' => 'Strict',
]);
session_start();
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

require __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/totp.php';
require_once __DIR__ . '/../includes/device_history.php';

function escapeHtml($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function formatLastUpdate($value): ?array
{
    if (!is_string($value) || trim($value) === '') {
        return null;
    }

    $utcTime = DateTimeImmutable::createFromFormat('!Y-m-d H:i:s', $value, new DateTimeZone('UTC'));
    $errors = DateTimeImmutable::getLastErrors();
    if ($utcTime === false
        || ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))
    ) {
        return null;
    }

    $kyivTime = $utcTime->setTimezone(new DateTimeZone('Europe/Kyiv'));

    return [
        'datetime' => $utcTime->format(DateTime::ATOM),
        'kyiv' => $kyivTime->format('d.m.Y H:i:s'),
        'utc' => $utcTime->format('Y-m-d H:i:s') . ' UTC',
    ];
}

function getConnectionStatus($value, int $now): array
{
    if (!is_string($value) || trim($value) === '') {
        return ['class' => 'unknown', 'label' => 'Немає даних', 'age' => null];
    }

    $lastUpdate = DateTimeImmutable::createFromFormat('!Y-m-d H:i:s', $value, new DateTimeZone('UTC'));
    $errors = DateTimeImmutable::getLastErrors();
    if ($lastUpdate === false
        || ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))
    ) {
        return ['class' => 'unknown', 'label' => 'Немає даних', 'age' => null];
    }

    $elapsedSeconds = max(0, $now - $lastUpdate->getTimestamp());
    if ($elapsedSeconds <= 15 * 60) {
        $class = 'online';
        $label = 'Online';
    } elseif ($elapsedSeconds <= 61 * 60) {
        $class = 'warning';
        $label = 'Увага';
    } else {
        $class = 'offline';
        $label = 'Offline';
    }

    $elapsedMinutes = (int) floor($elapsedSeconds / 60);
    if ($elapsedMinutes < 1) {
        $age = 'щойно';
    } elseif ($elapsedMinutes < 60) {
        $age = $elapsedMinutes . ' хв тому';
    } else {
        $hours = intdiv($elapsedMinutes, 60);
        $minutes = $elapsedMinutes % 60;
        $age = $hours . ' год' . ($minutes > 0 ? ' ' . $minutes . ' хв' : '') . ' тому';
    }

    return ['class' => $class, 'label' => $label, 'age' => $age];
}

function postString(string $key, string $default = ''): string
{
    $value = $_POST[$key] ?? $default;
    if (!is_string($value)) {
        throw new InvalidArgumentException('Некоректні дані форми.');
    }

    return $value;
}

function hashPassword(string $password): string
{
    $hash = password_hash($password, PASSWORD_DEFAULT);
    if ($hash === false) {
        throw new RuntimeException('Не вдалося захешувати пароль.');
    }

    return $hash;
}

function setFlash(
    string $message,
    string $type = 'success',
    ?array $totpSetup = null,
    ?string $deviceToken = null,
    ?string $apiToken = null,
    ?array $invite = null
): void
{
    $_SESSION['admin_flash'] = [
        'message' => $message,
        'type' => $type,
        'totp_setup' => $totpSetup,
        'device_token' => $deviceToken,
        'api_token' => $apiToken,
        'invite' => $invite,
    ];
}

function redirectToAdmin(): void
{
    header('Location: admin.php');
    exit;
}

$now = time();
if (isset($_SESSION['admin_pending_user_id'])
    && (!isset($_SESSION['admin_pending_started']) || $now - (int) $_SESSION['admin_pending_started'] > 300)
) {
    unset($_SESSION['admin_pending_user_id'], $_SESSION['admin_pending_started']);
    setFlash('Час входу вичерпано. Увійдіть знову.', 'error');
}

$authenticatedUser = null;
if (isset($_SESSION['admin_user_id'])) {
    if (!isset($_SESSION['admin_last_activity']) || $now - (int) $_SESSION['admin_last_activity'] > 1800) {
        unset($_SESSION['admin_user_id'], $_SESSION['admin_last_activity'], $_SESSION['admin_password_hash']);
        session_regenerate_id(true);
        $_SESSION['admin_csrf'] = bin2hex(random_bytes(32));
        setFlash('Сесію завершено через бездіяльність. Увійдіть знову.', 'error');
    } else {
        $statement = $pdo->prepare("SELECT id, username, password_hash FROM users WHERE id = :id AND role = 'admin'");
        $statement->execute([':id' => (int) $_SESSION['admin_user_id']]);
        $authenticatedUser = $statement->fetch(PDO::FETCH_ASSOC);
        if (!$authenticatedUser
            || !isset($_SESSION['admin_password_hash'])
            || !is_string($_SESSION['admin_password_hash'])
            || !is_string($authenticatedUser['password_hash'])
            || !hash_equals($authenticatedUser['password_hash'], $_SESSION['admin_password_hash'])
        ) {
            unset($_SESSION['admin_user_id'], $_SESSION['admin_last_activity'], $_SESSION['admin_password_hash']);
            session_regenerate_id(true);
            $_SESSION['admin_csrf'] = bin2hex(random_bytes(32));
            setFlash('Облікові дані змінилися або обліковий запис більше не має доступу. Увійдіть знову.', 'error');
        } else {
            $_SESSION['admin_last_activity'] = $now;
        }
    }
}

if (!isset($_SESSION['admin_csrf'])) {
    $_SESSION['admin_csrf'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['admin_csrf'];

if (array_key_exists('device_json', $_GET)) {
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');

    if (!$authenticatedUser) {
        http_response_code(403);
        exit('{"error":"Authentication required."}');
    }

    $deviceId = $_GET['device_json'];
    if (!is_string($deviceId) || !preg_match('/\A[a-zA-Z0-9_-]{1,64}\z/', $deviceId)) {
        http_response_code(400);
        exit('{"error":"Invalid device ID."}');
    }

    $statement = $pdo->prepare('SELECT 1 FROM devices WHERE id = :id');
    $statement->execute([':id' => $deviceId]);
    if ($statement->fetchColumn() === false) {
        http_response_code(404);
        exit('{"error":"Device not found."}');
    }

    $storageDirectory = realpath(__DIR__ . '/../storage');
    if ($storageDirectory === false) {
        error_log('Could not resolve device storage directory.');
        http_response_code(500);
        exit('{"error":"Could not access device state."}');
    }

    $filePath = realpath($storageDirectory . DIRECTORY_SEPARATOR . $deviceId . '.json');
    $storagePrefix = $storageDirectory . DIRECTORY_SEPARATOR;
    if ($filePath === false
        || strncmp($filePath, $storagePrefix, strlen($storagePrefix)) !== 0
        || !is_file($filePath)
    ) {
        http_response_code(404);
        exit('{"error":"Device state file not found."}');
    }

    $contents = file_get_contents($filePath);
    if ($contents === false) {
        error_log('Could not read device state file: ' . $filePath);
        http_response_code(500);
        exit('{"error":"Could not read device state."}');
    }

    echo $contents;
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!is_string($submittedToken) || !hash_equals($csrfToken, $submittedToken)) {
        http_response_code(400);
        exit('Invalid request token.');
    }

    $action = postString('action');

    if ($action === 'login_password') {
        if (!empty($_SESSION['admin_login_locked_until']) && $now < (int) $_SESSION['admin_login_locked_until']) {
            setFlash('Забагато невдалих спроб. Спробуйте пізніше.', 'error');
            redirectToAdmin();
        }

        $username = trim(postString('username'));
        $password = postString('password');
        $statement = $pdo->prepare('SELECT id, password_hash, totp_secret FROM users WHERE username = :username AND role = :role');
        $statement->execute([':username' => $username, ':role' => 'admin']);
        $user = $statement->fetch(PDO::FETCH_ASSOC);

        if ($user
            && password_verify($password, $user['password_hash'])
            && is_string($user['totp_secret'])
            && $user['totp_secret'] !== ''
        ) {
            session_regenerate_id(true);
            $_SESSION['admin_csrf'] = bin2hex(random_bytes(32));
            $_SESSION['admin_pending_user_id'] = (int) $user['id'];
            $_SESSION['admin_pending_started'] = $now;
            unset($_SESSION['admin_flash']);
            unset($_SESSION['admin_user_id'], $_SESSION['admin_last_activity'], $_SESSION['admin_password_hash']);
        } else {
            $failures = (int) ($_SESSION['admin_login_failures'] ?? 0) + 1;
            $_SESSION['admin_login_failures'] = $failures;
            if ($failures >= 5) {
                $_SESSION['admin_login_locked_until'] = $now + 300;
                $_SESSION['admin_login_failures'] = 0;
            }
            setFlash('Не вдалося увійти. Перевірте дані адміністратора та налаштування 2FA.', 'error');
        }
        redirectToAdmin();
    }

    if ($action === 'login_totp') {
        if (!empty($_SESSION['admin_login_locked_until']) && $now < (int) $_SESSION['admin_login_locked_until']) {
            setFlash('Забагато невдалих спроб. Спробуйте пізніше.', 'error');
            redirectToAdmin();
        }

        $pendingUserId = (int) ($_SESSION['admin_pending_user_id'] ?? 0);
        $pendingStarted = (int) ($_SESSION['admin_pending_started'] ?? 0);
        if (!$pendingUserId || !$pendingStarted || $now - $pendingStarted > 300) {
            unset($_SESSION['admin_pending_user_id'], $_SESSION['admin_pending_started']);
            setFlash('Час входу вичерпано. Увійдіть знову.', 'error');
            redirectToAdmin();
        }

        $statement = $pdo->prepare("SELECT totp_secret, password_hash FROM users WHERE id = :id AND role = 'admin'");
        $statement->execute([':id' => $pendingUserId]);
        $user = $statement->fetch(PDO::FETCH_ASSOC);
        $code = postString('totp_code');
        if ($user && is_string($user['totp_secret']) && verifyTotpCode($user['totp_secret'], $code, $now)) {
            session_regenerate_id(true);
            $_SESSION['admin_csrf'] = bin2hex(random_bytes(32));
            $_SESSION['admin_user_id'] = $pendingUserId;
            $_SESSION['admin_password_hash'] = $user['password_hash'];
            $_SESSION['admin_last_activity'] = $now;
            unset(
                $_SESSION['admin_pending_user_id'],
                $_SESSION['admin_pending_started'],
                $_SESSION['admin_login_failures'],
                $_SESSION['admin_login_locked_until']
            );
            setFlash('Вхід виконано.');
        } else {
            $failures = (int) ($_SESSION['admin_login_failures'] ?? 0) + 1;
            $_SESSION['admin_login_failures'] = $failures;
            if ($failures >= 5) {
                $_SESSION['admin_login_locked_until'] = $now + 300;
                $_SESSION['admin_login_failures'] = 0;
                unset($_SESSION['admin_pending_user_id'], $_SESSION['admin_pending_started']);
                setFlash('Забагато невдалих спроб. Спробуйте знову через 5 хвилин.', 'error');
            } else {
                setFlash('Невірний код автентифікатора.', 'error');
            }
        }
        redirectToAdmin();
    }

    if ($action === 'cancel_login') {
        unset($_SESSION['admin_pending_user_id'], $_SESSION['admin_pending_started']);
        redirectToAdmin();
    }

    if ($action === 'logout') {
        unset(
            $_SESSION['admin_user_id'],
            $_SESSION['admin_password_hash'],
            $_SESSION['admin_last_activity'],
            $_SESSION['admin_pending_user_id'],
            $_SESSION['admin_pending_started']
        );
        session_regenerate_id(true);
        $_SESSION['admin_csrf'] = bin2hex(random_bytes(32));
        setFlash('Ви вийшли з адмінки.');
        redirectToAdmin();
    }

    if (!$authenticatedUser) {
        http_response_code(403);
        exit('Authentication required.');
    }

    try {
        switch ($action) {
            case 'create_user': {
                $username = trim(postString('username'));
                $password = postString('password');
                $role = postString('role', 'user');
                if ($username === '' || strlen($username) > 64 || $password === '') {
                    throw new InvalidArgumentException('Вкажіть логін до 64 символів і пароль.');
                }
                if (!in_array($role, ['admin', 'user'], true)) {
                    throw new InvalidArgumentException('Некоректна роль користувача.');
                }

                $totpSecret = createTotpSecret();
                $statement = $pdo->prepare(
                    'INSERT INTO users (username, password_hash, totp_secret, role) VALUES (:username, :password_hash, :totp_secret, :role)'
                );
                $statement->execute([
                    ':username' => $username,
                    ':password_hash' => hashPassword($password),
                    ':totp_secret' => $totpSecret,
                    ':role' => $role,
                ]);
                $totpUri = 'otpauth://totp/' . rawurlencode('Micro-IoT-Cloud:' . $username)
                    . '?' . http_build_query([
                        'secret' => $totpSecret,
                        'issuer' => 'Micro-IoT-Cloud',
                        'algorithm' => 'SHA1',
                        'digits' => 6,
                        'period' => 30,
                    ]);
                setFlash('Користувача створено. Налаштуйте 2FA за QR-кодом нижче.', 'success', [
                    'username' => $username,
                    'secret' => $totpSecret,
                    'uri' => $totpUri,
                ]);
                break;
            }

            case 'create_user_invite': {
                $expirationOptions = [
                    '86400' => 86400,
                    '604800' => 604800,
                ];
                $expiration = postString('invite_expiration');
                if (!isset($expirationOptions[$expiration])) {
                    throw new InvalidArgumentException('Виберіть коректний термін дії запрошення.');
                }

                $token = bin2hex(random_bytes(32));
                $expiresAt = time() + $expirationOptions[$expiration];
                $statement = $pdo->prepare(
                    'INSERT INTO user_invites (token_hash, expires_at, created_by) '
                    . 'VALUES (:token_hash, :expires_at, :created_by)'
                );
                $statement->execute([
                    ':token_hash' => hash('sha256', $token),
                    ':expires_at' => $expiresAt,
                    ':created_by' => (int) $authenticatedUser['id'],
                ]);

                $invitePath = '../login/register.php?invite=' . rawurlencode($token);
                setFlash(
                    'Запрошення створено. Передайте посилання користувачу приватно.',
                    'success',
                    null,
                    null,
                    null,
                    [
                        'path' => $invitePath,
                        'expires_at' => gmdate('Y-m-d H:i:s', $expiresAt) . ' UTC',
                    ]
                );
                break;
            }

            case 'revoke_user_invite': {
                $inviteId = filter_var($_POST['invite_id'] ?? null, FILTER_VALIDATE_INT);
                if (!$inviteId) {
                    throw new InvalidArgumentException('Некоректне запрошення.');
                }

                $statement = $pdo->prepare(
                    'DELETE FROM user_invites '
                    . 'WHERE id = :id AND used_at IS NULL AND expires_at > :now'
                );
                $statement->execute([':id' => $inviteId, ':now' => time()]);
                if ($statement->rowCount() !== 1) {
                    throw new InvalidArgumentException('Запрошення вже використане, прострочене або не існує.');
                }

                setFlash('Запрошення відкликано.');
                break;
            }

            case 'update_user': {
                $userId = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
                $username = trim(postString('username'));
                $role = postString('role');
                $password = postString('new_password');
                if (!$userId || $username === '' || strlen($username) > 64) {
                    throw new InvalidArgumentException('Перевірте логін користувача.');
                }
                if (!in_array($role, ['admin', 'user'], true)) {
                    throw new InvalidArgumentException('Некоректна роль користувача.');
                }

                if ($password === '') {
                    $statement = $pdo->prepare('UPDATE users SET username = :username, role = :role WHERE id = :id');
                    $statement->execute([':username' => $username, ':role' => $role, ':id' => $userId]);
                } else {
                    $passwordHash = hashPassword($password);
                    $statement = $pdo->prepare(
                        'UPDATE users SET username = :username, role = :role, password_hash = :password_hash WHERE id = :id'
                    );
                    $statement->execute([
                        ':username' => $username,
                        ':role' => $role,
                        ':password_hash' => $passwordHash,
                        ':id' => $userId,
                    ]);
                    if ($userId === (int) $_SESSION['admin_user_id']) {
                        $_SESSION['admin_password_hash'] = $passwordHash;
                    }
                }
                setFlash('Параметри користувача збережено.');
                break;
            }

            case 'delete_user': {
                $userId = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
                if (!$userId) {
                    throw new InvalidArgumentException('Некоректний користувач.');
                }

                $pdo->beginTransaction();
                $statement = $pdo->prepare('DELETE FROM user_devices WHERE user_id = :user_id');
                $statement->execute([':user_id' => $userId]);

                $statement = $pdo->prepare('DELETE FROM users WHERE id = :id');
                $statement->execute([':id' => $userId]);
                if ($statement->rowCount() !== 1) {
                    $pdo->rollBack();
                    throw new InvalidArgumentException('Користувача не знайдено.');
                }

                $pdo->commit();
                setFlash('Користувача та його доступи до девайсів видалено.');
                break;
            }

            case 'show_api_token': {
                $userId = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
                if (!$userId) {
                    throw new InvalidArgumentException('Некоректний користувач.');
                }

                $statement = $pdo->prepare('SELECT api_token FROM users WHERE id = :id');
                $statement->execute([':id' => $userId]);
                $token = $statement->fetchColumn();
                if ($token === false) {
                    throw new InvalidArgumentException('Користувача не знайдено.');
                }
                if (!is_string($token) || $token === '') {
                    setFlash('Для користувача ще не створено API-токен.', 'error');
                    break;
                }

                setFlash('Наявний API-токен користувача:', 'success', null, null, $token);
                break;
            }

            case 'generate_api_token': {
                $userId = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
                if (!$userId) {
                    throw new InvalidArgumentException('Некоректний користувач.');
                }

                $token = bin2hex(random_bytes(32));
                $statement = $pdo->prepare('UPDATE users SET api_token = :token WHERE id = :id');
                $statement->execute([':token' => $token, ':id' => $userId]);
                if ($statement->rowCount() !== 1) {
                    throw new InvalidArgumentException('Користувача не знайдено.');
                }
                setFlash('API-токен користувача створено. Він показується лише зараз.', 'success', null, null, $token);
                break;
            }

            case 'reset_totp': {
                $userId = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
                if (!$userId) {
                    throw new InvalidArgumentException('Некоректний користувач.');
                }
                $statement = $pdo->prepare('SELECT username FROM users WHERE id = :id');
                $statement->execute([':id' => $userId]);
                $username = $statement->fetchColumn();
                if (!is_string($username)) {
                    throw new InvalidArgumentException('Користувача не знайдено.');
                }

                $secret = createTotpSecret();
                $statement = $pdo->prepare('UPDATE users SET totp_secret = :secret WHERE id = :id');
                $statement->execute([':secret' => $secret, ':id' => $userId]);
                $totpUri = 'otpauth://totp/' . rawurlencode('Micro-IoT-Cloud:' . $username)
                    . '?' . http_build_query([
                        'secret' => $secret,
                        'issuer' => 'Micro-IoT-Cloud',
                        'algorithm' => 'SHA1',
                        'digits' => 6,
                        'period' => 30,
                    ]);
                setFlash('Секрет 2FA замінено. Налаштуйте новий секрет за QR-кодом нижче.', 'success', [
                    'username' => $username,
                    'secret' => $secret,
                    'uri' => $totpUri,
                ]);
                break;
            }

            case 'create_device': {
                $deviceId = trim(postString('device_id'));
                $name = trim(postString('name'));
                if (!preg_match('/\A[a-zA-Z0-9_-]{1,64}\z/', $deviceId) || $name === '') {
                    throw new InvalidArgumentException('Вкажіть коректний device_id і назву.');
                }

                $token = bin2hex(random_bytes(32));
                $statement = $pdo->prepare('INSERT INTO devices (id, name, device_token) VALUES (:id, :name, :token)');
                $statement->execute([':id' => $deviceId, ':name' => $name, ':token' => $token]);
                setFlash('Девайс створено. Збережіть токен: він показується лише зараз.', 'success', null, $token);
                break;
            }

            case 'update_device': {
                $deviceId = postString('device_id');
                $name = trim(postString('name'));
                if ($name === '') {
                    throw new InvalidArgumentException('Назва пристрою не може бути порожньою.');
                }
                $statement = $pdo->prepare('UPDATE devices SET name = :name WHERE id = :id');
                $statement->execute([':name' => $name, ':id' => $deviceId]);
                setFlash('Назву пристрою збережено.');
                break;
            }

            case 'update_history_settings': {
                $deviceId = postString('device_id');
                $mode = postString('history_mode');
                $presets = deviceHistoryPresets();
                if (!preg_match('/\A[a-zA-Z0-9_-]{1,64}\z/', $deviceId)
                    || !isset($presets[$mode])
                ) {
                    throw new InvalidArgumentException('Некоректний режим історії або device_id.');
                }

                $preset = $presets[$mode];
                $pdo->beginTransaction();
                $statement = $pdo->prepare(
                    'UPDATE device_history_settings '
                    . 'SET enabled = :enabled, interval_seconds = :interval_seconds, '
                    . 'retention_seconds = :retention_seconds WHERE device_id = :device_id'
                );
                $statement->execute([
                    ':enabled' => $preset['enabled'],
                    ':interval_seconds' => $preset['interval_seconds'],
                    ':retention_seconds' => $preset['retention_seconds'],
                    ':device_id' => $deviceId,
                ]);
                if ($statement->rowCount() !== 1) {
                    $pdo->rollBack();
                    throw new InvalidArgumentException('Девайс не знайдено.');
                }

                if ($preset['enabled'] === 0) {
                    deleteDeviceHistory(dirname(__DIR__) . '/storage', $deviceId);
                }
                $pdo->commit();
                setFlash('Налаштування історії збережено.');
                break;
            }

            case 'regenerate_device_token': {
                $deviceId = postString('device_id');
                $token = bin2hex(random_bytes(32));
                $statement = $pdo->prepare('UPDATE devices SET device_token = :token WHERE id = :id');
                $statement->execute([':token' => $token, ':id' => $deviceId]);
                if ($statement->rowCount() !== 1) {
                    throw new InvalidArgumentException('Девайс не знайдено.');
                }
                setFlash('Токен замінено. Збережіть його та оновіть конфігурацію пристрою.', 'success', null, $token);
                break;
            }

            case 'set_device_token': {
                $deviceId = postString('device_id');
                $token = trim(postString('device_token'));
                if ($token === '' || strlen($token) > 256 || !preg_match('/\A[\x21-\x7E]+\z/', $token)) {
                    throw new InvalidArgumentException('Токен має містити 1–256 друкованих ASCII-символів без пробілів.');
                }

                $statement = $pdo->prepare('SELECT 1 FROM devices WHERE id = :id');
                $statement->execute([':id' => $deviceId]);
                if ($statement->fetchColumn() === false) {
                    throw new InvalidArgumentException('Девайс не знайдено.');
                }

                $statement = $pdo->prepare('UPDATE devices SET device_token = :token WHERE id = :id');
                $statement->execute([':token' => $token, ':id' => $deviceId]);
                setFlash('Встановлено заданий токен. Він має точно збігатися з токеном у прошивці пристрою.');
                break;
            }

            case 'update_acl': {
                $userId = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
                $selectedIds = $_POST['device_ids'] ?? [];
                if (!$userId || !is_array($selectedIds)) {
                    throw new InvalidArgumentException('Некоректні параметри доступу.');
                }

                $existingStatement = $pdo->prepare('SELECT device_id, permission FROM user_devices WHERE user_id = :user_id');
                $existingStatement->execute([':user_id' => $userId]);
                $existingPermissions = $existingStatement->fetchAll(PDO::FETCH_KEY_PAIR);
                $knownIds = $pdo->query('SELECT id FROM devices')->fetchAll(PDO::FETCH_COLUMN);
                $knownIds = array_fill_keys($knownIds, true);
                $selectedIds = array_values(array_unique(array_filter(
                    $selectedIds,
                    static function ($id) use ($knownIds): bool {
                        return is_string($id) && isset($knownIds[$id]);
                    }
                )));

                $pdo->beginTransaction();
                $statement = $pdo->prepare('DELETE FROM user_devices WHERE user_id = :user_id');
                $statement->execute([':user_id' => $userId]);
                $insert = $pdo->prepare(
                    'INSERT INTO user_devices (user_id, device_id, permission) VALUES (:user_id, :device_id, :permission)'
                );
                foreach ($selectedIds as $deviceId) {
                    $insert->execute([
                        ':user_id' => $userId,
                        ':device_id' => $deviceId,
                        ':permission' => $existingPermissions[$deviceId] ?? 'read',
                    ]);
                }
                $pdo->commit();
                setFlash('Доступи до пристроїв збережено.');
                break;
            }

            default:
                throw new InvalidArgumentException('Невідома дія.');
        }
    } catch (InvalidArgumentException $error) {
        setFlash($error->getMessage(), 'error');
    } catch (PDOException $error) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('Admin database operation failed: ' . $error->getMessage());
        setFlash('Не вдалося зберегти зміни. Перевірте унікальність логіна або device_id.', 'error');
    } catch (RuntimeException $error) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('Admin device history operation failed: ' . $error->getMessage());
        setFlash('Не вдалося зберегти налаштування історії.', 'error');
    }

    header('Location: admin.php');
    exit;
}

$flash = $_SESSION['admin_flash'] ?? null;
unset($_SESSION['admin_flash']);

$devices = [];
$users = [];
$userDevices = [];
$activeInvites = [];
if ($authenticatedUser) {
    $devices = $pdo->query(
        'SELECT d.id, d.name, d.last_payload, d.last_update, '
        . 'settings.enabled AS history_enabled, '
        . 'settings.interval_seconds AS history_interval_seconds, '
        . 'settings.retention_seconds AS history_retention_seconds '
        . 'FROM devices AS d '
        . 'INNER JOIN device_history_settings AS settings ON settings.device_id = d.id '
        . 'ORDER BY d.name, d.id'
    )->fetchAll(PDO::FETCH_ASSOC);
    $users = $pdo->query('SELECT id, username, role, created_at FROM users ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
    $userDeviceStatement = $pdo->query('SELECT user_id, device_id FROM user_devices');
    foreach ($userDeviceStatement->fetchAll(PDO::FETCH_ASSOC) as $link) {
        $userDevices[(int) $link['user_id']][$link['device_id']] = true;
    }
    $inviteStatement = $pdo->prepare(
        'SELECT invites.id, invites.created_at, invites.expires_at, creator.username AS creator_username '
        . 'FROM user_invites AS invites '
        . 'LEFT JOIN users AS creator ON creator.id = invites.created_by '
        . 'WHERE invites.used_at IS NULL AND invites.expires_at > :now '
        . 'ORDER BY invites.expires_at, invites.id'
    );
    $inviteStatement->execute([':now' => time()]);
    $activeInvites = $inviteStatement->fetchAll(PDO::FETCH_ASSOC);
}
?>
<!doctype html>
<html lang="uk">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Адміністрування хмари</title>
    <link rel="stylesheet" href="admin.css?v=<?= (int) @filemtime(__DIR__ . '/admin.css') ?>">
    <script>try { if (localStorage.getItem('adminView') === 'mobile') document.documentElement.classList.add('mobile'); } catch (e) {}</script>
</head>
<body>
    <header class="top">
        <h1>Адміністрування хмари</h1>
        <?php if ($authenticatedUser): ?>
        <div class="session">
            <span class="muted">Ви увійшли як <?= escapeHtml($authenticatedUser['username']) ?>. Сесія завершиться після 30 хвилин бездіяльності.</span>
            <form method="post">
                <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                <input type="hidden" name="action" value="logout">
                <button type="submit">Вийти</button>
            </form>
        </div>
        <?php endif; ?>
        <a class="help-link" href="help.php">Довідка</a>
        <a class="help-link" href="api-tester.html">Тестер POST</a>
        <button type="button" id="view-toggle" class="view-toggle"></button>
    </header>

    <?php if (!$authenticatedUser): ?>
        <section class="panel auth-panel">
            <?php if (is_array($flash)): ?>
                <div class="notice <?= escapeHtml($flash['type'] ?? '') ?>"><?= escapeHtml($flash['message'] ?? '') ?></div>
            <?php endif; ?>

            <?php if (isset($_SESSION['admin_pending_user_id'])): ?>
                <h2>Підтвердження 2FA</h2>
                <p>Введіть шестизначний код із Google Authenticator.</p>
                <form method="post" class="stack">
                    <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                    <input type="hidden" name="action" value="login_totp">
                    <label>Код автентифікатора
                        <input type="text" name="totp_code" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" maxlength="6" required autofocus>
                    </label>
                    <button type="submit" class="primary">Підтвердити вхід</button>
                </form>
                <form method="post" class="stack">
                    <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                    <input type="hidden" name="action" value="cancel_login">
                    <button type="submit">Скасувати</button>
                </form>
            <?php else: ?>
                <h2>Вхід адміністратора</h2>
                <form method="post" class="stack">
                    <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                    <input type="hidden" name="action" value="login_password">
                    <label>Логін
                        <input type="text" name="username" autocomplete="username" maxlength="64" required autofocus>
                    </label>
                    <label>Пароль
                        <input type="password" name="password" autocomplete="current-password" required>
                    </label>
                    <button type="submit" class="primary">Продовжити</button>
                </form>
            <?php endif; ?>
        </section>
    <?php else: ?>

    <?php if (is_array($flash)): ?>
        <div class="notice <?= escapeHtml($flash['type'] ?? '') ?>">
            <?= escapeHtml($flash['message'] ?? '') ?>
            <?php if (!empty($flash['device_token'])): ?>
                <p>Новий токен пристрою: <code><?= escapeHtml($flash['device_token']) ?></code></p>
            <?php endif; ?>
            <?php if (!empty($flash['api_token'])): ?>
                <p>API-токен користувача: <code><?= escapeHtml($flash['api_token']) ?></code></p>
            <?php endif; ?>
            <?php if (!empty($flash['totp_setup'])): ?>
                <h3>Налаштування 2FA для <?= escapeHtml($flash['totp_setup']['username']) ?></h3>
                <div class="totp-qr" data-otpauth="<?= escapeHtml($flash['totp_setup']['uri']) ?>"></div>
                <p>Якщо сканування QR-коду недоступне, введіть ключ вручну: <code><?= escapeHtml($flash['totp_setup']['secret']) ?></code></p>
                <p class="muted">Цей секрет показано одноразово. Збережіть його в застосунку автентифікації.</p>
            <?php endif; ?>
            <?php if (!empty($flash['invite']) && is_array($flash['invite'])): ?>
                <h3>Посилання-запрошення</h3>
                <div class="invite-link-row">
                    <label>Посилання (скопіюйте та надішліть користувачу)
                        <input type="text" value="<?= escapeHtml($flash['invite']['path']) ?>" data-invite-path readonly>
                    </label>
                    <button type="button" data-copy-invite>Копіювати</button>
                </div>
                <p class="muted">Чинне до <?= escapeHtml($flash['invite']['expires_at']) ?>. Передавайте посилання приватно через HTTPS.</p>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <h2>Девайси</h2>
    <div class="panel">
        <table class="devices">
            <thead><tr><th>Назва</th><th>device_id / URL</th><th>Стан пристрою</th><th>Стан зв'язку</th><th>Останній зв'язок</th><th>Історія</th><th>Керування</th></tr></thead>
            <tbody>
            <?php $statusCheckedAt = time(); ?>
            <?php foreach ($devices as $device): ?>
                <?php
                $payload = json_decode((string) $device['last_payload'], true);
                $status = is_array($payload) && array_key_exists('connected', $payload)
                    ? ($payload['connected'] === true ? 'Підключений' : ($payload['connected'] === false ? 'Відключений' : 'Невідомо'))
                    : 'Невідомо';
                $lastUpdate = formatLastUpdate($device['last_update']);
                $connectionStatus = getConnectionStatus($device['last_update'], $statusCheckedAt);
                $historySettings = [
                    'enabled' => $device['history_enabled'],
                    'interval_seconds' => $device['history_interval_seconds'],
                    'retention_seconds' => $device['history_retention_seconds'],
                ];
                $historyMode = deviceHistoryPresetKey($historySettings);
                ?>
                <tr>
                    <td data-label="Назва">
                        <form class="inline" method="post">
                            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                            <input type="hidden" name="action" value="update_device">
                            <input type="hidden" name="device_id" value="<?= escapeHtml($device['id']) ?>">
                            <input type="text" name="name" value="<?= escapeHtml($device['name']) ?>" aria-label="Назва девайса" required>
                            <button type="submit">Зберегти</button>
                        </form>
                    </td>
                    <td data-label="device_id / URL">
                        <a href="admin.php?device_json=<?= rawurlencode((string) $device['id']) ?>"><code><?= escapeHtml($device['id']) ?></code></a>
                    </td>
                    <td data-label="Стан пристрою"><?= escapeHtml($status) ?></td>
                    <td data-label="Стан зв'язку">
                        <span class="connection-status">
                            <span class="connection-status__dot connection-status__dot--<?= escapeHtml($connectionStatus['class']) ?>" aria-hidden="true"></span>
                            <span><?= escapeHtml($connectionStatus['label']) ?></span>
                            <?php if ($connectionStatus['age'] !== null): ?>
                                <span class="muted">· <?= escapeHtml($connectionStatus['age']) ?></span>
                            <?php endif; ?>
                        </span>
                    </td>
                    <td data-label="Останній зв'язок">
                        <?php if ($lastUpdate): ?>
                            <time datetime="<?= escapeHtml($lastUpdate['datetime']) ?>">
                                <?= escapeHtml($lastUpdate['kyiv']) ?> <span class="muted">(Київ)</span><br>
                                <span class="muted"><?= escapeHtml($lastUpdate['utc']) ?></span>
                            </time>
                        <?php else: ?>
                            <?= escapeHtml($device['last_update'] ?? '—') ?>
                        <?php endif; ?>
                    </td>
                    <td data-label="Історія">
                        <form method="post" class="stack" onsubmit="return this.history_mode.value !== 'off' || confirm('Вимкнути історію та видалити всі збережені записи цього девайса?');">
                            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                            <input type="hidden" name="action" value="update_history_settings">
                            <input type="hidden" name="device_id" value="<?= escapeHtml($device['id']) ?>">
                            <label>Режим
                                <select name="history_mode">
                                    <?php foreach (deviceHistoryPresets() as $mode => $preset): ?>
                                        <option value="<?= escapeHtml($mode) ?>" <?= $historyMode === $mode ? 'selected' : '' ?>><?= escapeHtml($preset['label']) ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </label>
                            <button type="submit">Зберегти</button>
                        </form>
                    </td>
                    <td data-label="Керування">
                        <form method="post" onsubmit="return confirm('Згенерувати новий токен? Старий токен одразу перестане працювати.');">
                            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                            <input type="hidden" name="action" value="regenerate_device_token">
                            <input type="hidden" name="device_id" value="<?= escapeHtml($device['id']) ?>">
                            <button type="submit">Згенерувати новий токен</button>
                        </form>
                        <form method="post" class="inline">
                            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                            <input type="hidden" name="action" value="set_device_token">
                            <input type="hidden" name="device_id" value="<?= escapeHtml($device['id']) ?>">
                            <label>Токен із прошивки
                                <input type="password" name="device_token" maxlength="256" autocomplete="new-password" required>
                            </label>
                            <button type="submit" onclick="return confirm('Замінити токен пристрою? Старий токен одразу перестане працювати.');">Встановити токен</button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            <?php if (!$devices): ?><tr><td colspan="7" class="muted">У базі поки немає девайсів.</td></tr><?php endif; ?>
            </tbody>
        </table>
    </div>

    <div class="panel">
        <h3>Додати девайс</h3>
        <form class="inline" method="post">
            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
            <input type="hidden" name="action" value="create_device">
            <label>device_id <input type="text" name="device_id" maxlength="64" pattern="[a-zA-Z0-9_-]+" required></label>
            <label>Назва <input type="text" name="name" required></label>
            <button type="submit" class="primary">Створити й згенерувати токен</button>
        </form>
    </div>

    <h2>Користувачі</h2>
    <div class="panel">
        <table class="users">
            <thead><tr><th>ID</th><th>Облікові дані</th><th>Створено</th><th>Доступ до девайсів</th><th>API-токен</th><th>2FA</th></tr></thead>
            <tbody>
            <?php foreach ($users as $user): ?>
                <tr>
                    <td data-label="ID"><?= (int) $user['id'] ?></td>
                    <td data-label="Облікові дані">
                        <form method="post" class="stack">
                            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                            <input type="hidden" name="action" value="update_user">
                            <input type="hidden" name="user_id" value="<?= (int) $user['id'] ?>">
                            <label>Логін<input type="text" name="username" value="<?= escapeHtml($user['username']) ?>" maxlength="64" required></label>
                            <label>Роль
                                <select name="role">
                                    <option value="user" <?= $user['role'] === 'user' ? 'selected' : '' ?>>user</option>
                                    <option value="admin" <?= $user['role'] === 'admin' ? 'selected' : '' ?>>admin</option>
                                </select>
                            </label>
                            <label>Новий пароль<input type="password" name="new_password" autocomplete="new-password"></label>
                            <button type="submit">Зберегти</button>
                        </form>
                    </td>
                    <td data-label="Створено"><?= escapeHtml($user['created_at'] ?? '—') ?></td>
                    <td data-label="Доступ до девайсів">
                        <form method="post" class="stack">
                            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                            <input type="hidden" name="action" value="update_acl">
                            <input type="hidden" name="user_id" value="<?= (int) $user['id'] ?>">
                            <div class="acl-list">
                                <?php foreach ($devices as $device): ?>
                                    <label>
                                        <input type="checkbox" name="device_ids[]" value="<?= escapeHtml($device['id']) ?>"
                                            <?= isset($userDevices[(int) $user['id']][$device['id']]) ? 'checked' : '' ?>>
                                        <?= escapeHtml($device['name']) ?> <span class="muted">(<?= escapeHtml($device['id']) ?>)</span>
                                    </label>
                                <?php endforeach; ?>
                                <?php if (!$devices): ?><span class="muted">Девайсів поки немає.</span><?php endif; ?>
                            </div>
                            <button type="submit">Зберегти доступи</button>
                        </form>
                    </td>
                    <td data-label="API-токен">
                        <form method="post">
                            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                            <input type="hidden" name="action" value="show_api_token">
                            <input type="hidden" name="user_id" value="<?= (int) $user['id'] ?>">
                            <button type="submit">Показати наявний токен</button>
                        </form>
                        <form method="post" onsubmit="return confirm('Згенерувати новий API-токен? Попередній токен одразу перестане працювати.');">
                            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                            <input type="hidden" name="action" value="generate_api_token">
                            <input type="hidden" name="user_id" value="<?= (int) $user['id'] ?>">
                            <button type="submit">Згенерувати / перевипустити</button>
                        </form>
                    </td>
                    <td data-label="2FA">
                        <form method="post" onsubmit="return confirm('Скинути 2FA та замінити поточний секрет?');">
                            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                            <input type="hidden" name="action" value="reset_totp">
                            <input type="hidden" name="user_id" value="<?= (int) $user['id'] ?>">
                            <button type="submit">Скинути 2FA</button>
                        </form>
                        <form method="post" onsubmit="return confirm('Видалити користувача та всі його зв’язки з девайсами? Цю дію не можна скасувати.');">
                            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                            <input type="hidden" name="action" value="delete_user">
                            <input type="hidden" name="user_id" value="<?= (int) $user['id'] ?>">
                            <button type="submit" class="danger">Видалити користувача</button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            <?php if (!$users): ?><tr><td colspan="6" class="muted">У базі поки немає користувачів.</td></tr><?php endif; ?>
            </tbody>
        </table>
    </div>

    <div class="panel">
        <h3>Додати користувача</h3>
        <form class="inline" method="post">
            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
            <input type="hidden" name="action" value="create_user">
            <label>Логін <input type="text" name="username" maxlength="64" required></label>
            <label>Пароль <input type="password" name="password" autocomplete="new-password" required></label>
            <label>Роль
                <select name="role"><option value="user">user</option><option value="admin">admin</option></select>
            </label>
            <button type="submit" class="primary">Створити користувача</button>
        </form>
        <p class="muted">Для нового користувача код згенерує секрет 2FA і покаже QR-код після створення.</p>
    </div>

    <div class="panel">
        <h3>Запрошення користувачів</h3>
        <form class="inline" method="post">
            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
            <input type="hidden" name="action" value="create_user_invite">
            <label>Термін дії
                <select name="invite_expiration">
                    <option value="86400">24 години</option>
                    <option value="604800" selected>7 днів</option>
                </select>
            </label>
            <button type="submit" class="primary">Створити запрошення</button>
        </form>
        <p class="muted">Запрошення одноразове. Акаунт створиться після налаштування й підтвердження 2FA; доступ до пристроїв призначає адміністратор.</p>

        <?php if ($activeInvites): ?>
            <h3>Активні запрошення</h3>
            <table class="invites">
                <thead><tr><th>Створено</th><th>Чинне до (UTC)</th><th>Створив</th><th>Керування</th></tr></thead>
                <tbody>
                <?php foreach ($activeInvites as $invite): ?>
                    <tr>
                        <td data-label="Створено"><?= escapeHtml($invite['created_at']) ?></td>
                        <td data-label="Чинне до (UTC)"><?= gmdate('Y-m-d H:i:s', (int) $invite['expires_at']) ?></td>
                        <td data-label="Створив"><?= escapeHtml($invite['creator_username'] ?? '—') ?></td>
                        <td data-label="Керування">
                            <form method="post" onsubmit="return confirm('Відкликати це запрошення? Посилання одразу перестане працювати.');">
                                <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                                <input type="hidden" name="action" value="revoke_user_invite">
                                <input type="hidden" name="invite_id" value="<?= (int) $invite['id'] ?>">
                                <button type="submit" class="danger">Відкликати</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php else: ?>
            <p class="muted">Немає активних запрошень.</p>
        <?php endif; ?>
    </div>

    <script src="vendor/qrcode-generator.js"></script>
    <script>
        document.querySelectorAll('.totp-qr[data-otpauth]').forEach((element) => {
            const qr = qrcode(0, 'M');
            qr.addData(element.dataset.otpauth, 'Byte');
            qr.make();
            element.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
        });
        document.querySelectorAll('[data-invite-path]').forEach((input) => {
            input.value = new URL(input.value, window.location.href).href;
            const button = input.closest('.invite-link-row').querySelector('[data-copy-invite]');
            button.addEventListener('click', () => {
                if (!navigator.clipboard || !window.isSecureContext) {
                    input.select();
                    button.textContent = 'Скопіюйте виділене посилання';
                    return;
                }
                navigator.clipboard.writeText(input.value).then(() => {
                    button.textContent = 'Скопійовано';
                }).catch(() => {
                    input.select();
                    button.textContent = 'Скопіюйте виділене посилання';
                });
            });
        });
    </script>
    <?php endif; ?>
    <script>
        (function () {
            const root = document.documentElement;
            const button = document.getElementById('view-toggle');
            const sync = () => { button.textContent = root.classList.contains('mobile') ? 'Вигляд для ПК' : 'Вигляд для телефона'; };
            button.addEventListener('click', () => {
                const mobile = root.classList.toggle('mobile');
                try { localStorage.setItem('adminView', mobile ? 'mobile' : 'desktop'); } catch (e) {}
                sync();
            });
            sync();
        })();
    </script>
</body>
</html>
