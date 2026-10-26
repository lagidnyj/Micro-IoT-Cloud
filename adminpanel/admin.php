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

function base32Encode(string $value): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (unpack('C*', $value) as $byte) {
        $bits .= str_pad(decbin($byte), 8, '0', STR_PAD_LEFT);
    }

    $encoded = '';
    foreach (str_split($bits, 5) as $chunk) {
        $encoded .= $alphabet[bindec(str_pad($chunk, 5, '0'))];
    }

    return $encoded;
}

function createTotpSecret(): string
{
    return base32Encode(random_bytes(20));
}

function verifyTotpCode(string $secret, string $code, int $timestamp): bool
{
    if (!preg_match('/\A[0-9]{6}\z/', $code) || !preg_match('/\A[A-Z2-7]+\z/', $secret)) {
        return false;
    }

    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($secret) as $character) {
        $value = strpos($alphabet, $character);
        if ($value === false) {
            return false;
        }
        $bits .= str_pad(decbin($value), 5, '0', STR_PAD_LEFT);
    }

    $key = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) === 8) {
            $key .= chr(bindec($byte));
        }
    }
    if ($key === '') {
        return false;
    }

    $counter = (int) floor($timestamp / 30);
    for ($offset = -1; $offset <= 1; $offset++) {
        $timeCounter = $counter + $offset;
        $message = pack('N2', ($timeCounter >> 32) & 0xffffffff, $timeCounter & 0xffffffff);
        $hash = hash_hmac('sha1', $message, $key, true);
        $position = ord($hash[19]) & 0x0f;
        $binary = ((ord($hash[$position]) & 0x7f) << 24)
            | ((ord($hash[$position + 1]) & 0xff) << 16)
            | ((ord($hash[$position + 2]) & 0xff) << 8)
            | (ord($hash[$position + 3]) & 0xff);
        $expectedCode = str_pad((string) ($binary % 1000000), 6, '0', STR_PAD_LEFT);
        if (hash_equals($expectedCode, $code)) {
            return true;
        }
    }

    return false;
}

function setFlash(
    string $message,
    string $type = 'success',
    ?array $totpSetup = null,
    ?string $deviceToken = null,
    ?string $apiToken = null
): void
{
    $_SESSION['admin_flash'] = [
        'message' => $message,
        'type' => $type,
        'totp_setup' => $totpSetup,
        'device_token' => $deviceToken,
        'api_token' => $apiToken,
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
        unset($_SESSION['admin_user_id'], $_SESSION['admin_last_activity']);
        session_regenerate_id(true);
        $_SESSION['admin_csrf'] = bin2hex(random_bytes(32));
        setFlash('Сесію завершено через бездіяльність. Увійдіть знову.', 'error');
    } else {
        $statement = $pdo->prepare("SELECT id, username FROM users WHERE id = :id AND role = 'admin'");
        $statement->execute([':id' => (int) $_SESSION['admin_user_id']]);
        $authenticatedUser = $statement->fetch(PDO::FETCH_ASSOC);
        if (!$authenticatedUser) {
            unset($_SESSION['admin_user_id'], $_SESSION['admin_last_activity']);
            session_regenerate_id(true);
            $_SESSION['admin_csrf'] = bin2hex(random_bytes(32));
            setFlash('Обліковий запис адміністратора більше не має доступу. Увійдіть знову.', 'error');
        } else {
            $_SESSION['admin_last_activity'] = $now;
        }
    }
}

if (!isset($_SESSION['admin_csrf'])) {
    $_SESSION['admin_csrf'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['admin_csrf'];

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
            unset($_SESSION['admin_user_id'], $_SESSION['admin_last_activity']);
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

        $statement = $pdo->prepare("SELECT totp_secret FROM users WHERE id = :id AND role = 'admin'");
        $statement->execute([':id' => $pendingUserId]);
        $secret = $statement->fetchColumn();
        $code = postString('totp_code');
        if (is_string($secret) && verifyTotpCode($secret, $code, $now)) {
            session_regenerate_id(true);
            $_SESSION['admin_csrf'] = bin2hex(random_bytes(32));
            $_SESSION['admin_user_id'] = $pendingUserId;
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
                    $statement = $pdo->prepare(
                        'UPDATE users SET username = :username, role = :role, password_hash = :password_hash WHERE id = :id'
                    );
                    $statement->execute([
                        ':username' => $username,
                        ':role' => $role,
                        ':password_hash' => hashPassword($password),
                        ':id' => $userId,
                    ]);
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
    }

    header('Location: admin.php');
    exit;
}

$flash = $_SESSION['admin_flash'] ?? null;
unset($_SESSION['admin_flash']);

$devices = [];
$users = [];
$userDevices = [];
if ($authenticatedUser) {
    $devices = $pdo->query('SELECT id, name, last_payload, last_update FROM devices ORDER BY name, id')->fetchAll(PDO::FETCH_ASSOC);
    $users = $pdo->query('SELECT id, username, role, created_at FROM users ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
    $userDeviceStatement = $pdo->query('SELECT user_id, device_id FROM user_devices');
    foreach ($userDeviceStatement->fetchAll(PDO::FETCH_ASSOC) as $link) {
        $userDevices[(int) $link['user_id']][$link['device_id']] = true;
    }
}
?>
<!doctype html>
<html lang="uk">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Адміністрування хмари</title>
    <style>
        :root { color-scheme: light; font: 15px/1.45 system-ui, sans-serif; }
        body { max-width: 1200px; margin: 2rem auto; padding: 0 1rem; color: #17202a; background: #f4f6f8; }
        h1, h2 { line-height: 1.2; }
        h2 { margin-top: 2.5rem; }
        .warning, .notice { padding: 1rem; margin: 1rem 0; border-radius: .4rem; }
        .warning { color: #681b1b; background: #ffebeb; border: 1px solid #d99; }
        .notice { background: #e9f3ff; border: 1px solid #9bc5ee; overflow-wrap: anywhere; }
        .error { color: #8a1c1c; }
        .success { color: #14532d; }
        .panel { background: white; border: 1px solid #d9dee5; border-radius: .5rem; padding: 1rem; margin: 1rem 0; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; vertical-align: top; padding: .65rem; border-bottom: 1px solid #e4e8ed; }
        th { white-space: nowrap; }
        input, select, button { font: inherit; padding: .4rem .55rem; }
        input[type="text"], input[type="password"] { max-width: 100%; box-sizing: border-box; }
        button { cursor: pointer; }
        form.inline { display: flex; flex-wrap: wrap; align-items: center; gap: .4rem; }
        .acl-list { display: grid; gap: .35rem; margin-bottom: .5rem; }
        .acl-list label { display: flex; gap: .4rem; align-items: baseline; }
        .muted { color: #5b6570; font-size: .9rem; }
        .totp-qr { width: 190px; height: 190px; margin: .75rem 0; }
        .totp-qr svg { width: 100%; height: 100%; }
        code { overflow-wrap: anywhere; }
        .auth-panel { max-width: 420px; margin: 3rem auto; }
    </style>
</head>
<body>
    <h1>Адміністрування хмари</h1>

    <?php if (!$authenticatedUser): ?>
        <section class="panel auth-panel">
            <?php if (is_array($flash)): ?>
                <div class="notice <?= escapeHtml($flash['type'] ?? '') ?>"><?= escapeHtml($flash['message'] ?? '') ?></div>
            <?php endif; ?>

            <?php if (isset($_SESSION['admin_pending_user_id'])): ?>
                <h2>Підтвердження 2FA</h2>
                <p>Введіть шестизначний код із Google Authenticator.</p>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                    <input type="hidden" name="action" value="login_totp">
                    <label>Код автентифікатора
                        <input type="text" name="totp_code" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" maxlength="6" required autofocus>
                    </label>
                    <button type="submit">Підтвердити вхід</button>
                </form>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                    <input type="hidden" name="action" value="cancel_login">
                    <button type="submit">Скасувати</button>
                </form>
            <?php else: ?>
                <h2>Вхід адміністратора</h2>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                    <input type="hidden" name="action" value="login_password">
                    <label>Логін
                        <input type="text" name="username" autocomplete="username" maxlength="64" required autofocus>
                    </label><br>
                    <label>Пароль
                        <input type="password" name="password" autocomplete="current-password" required>
                    </label><br>
                    <button type="submit">Продовжити</button>
                </form>
            <?php endif; ?>
        </section>
    <?php else: ?>
    <p class="muted">Ви увійшли як <?= escapeHtml($authenticatedUser['username']) ?>.
        Сесія завершиться після 30 хвилин бездіяльності.</p>
    <form method="post">
        <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
        <input type="hidden" name="action" value="logout">
        <button type="submit">Вийти</button>
    </form>

    <?php if (is_array($flash)): ?>
        <div class="notice <?= escapeHtml($flash['type'] ?? '') ?>">
            <?= escapeHtml($flash['message'] ?? '') ?>
            <?php if (!empty($flash['device_token'])): ?>
                <p>Новий токен пристрою: <code><?= escapeHtml($flash['device_token']) ?></code></p>
            <?php endif; ?>
            <?php if (!empty($flash['api_token'])): ?>
                <p>API-токен користувача (збережіть зараз): <code><?= escapeHtml($flash['api_token']) ?></code></p>
            <?php endif; ?>
            <?php if (!empty($flash['totp_setup'])): ?>
                <h3>Налаштування 2FA для <?= escapeHtml($flash['totp_setup']['username']) ?></h3>
                <div class="totp-qr" data-otpauth="<?= escapeHtml($flash['totp_setup']['uri']) ?>"></div>
                <p>Якщо сканування QR-коду недоступне, введіть ключ вручну: <code><?= escapeHtml($flash['totp_setup']['secret']) ?></code></p>
                <p class="muted">Цей секрет показано одноразово. Збережіть його в застосунку автентифікації.</p>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <h2>Девайси</h2>
    <div class="panel">
        <table>
            <thead><tr><th>Назва</th><th>device_id</th><th>Статус</th><th>Останній зв'язок</th><th>Керування</th></tr></thead>
            <tbody>
            <?php foreach ($devices as $device): ?>
                <?php
                $payload = json_decode((string) $device['last_payload'], true);
                $status = is_array($payload) && array_key_exists('connected', $payload)
                    ? ($payload['connected'] === true ? 'Підключений' : ($payload['connected'] === false ? 'Відключений' : 'Невідомо'))
                    : 'Невідомо';
                $lastUpdate = formatLastUpdate($device['last_update']);
                ?>
                <tr>
                    <td>
                        <form class="inline" method="post">
                            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                            <input type="hidden" name="action" value="update_device">
                            <input type="hidden" name="device_id" value="<?= escapeHtml($device['id']) ?>">
                            <input type="text" name="name" value="<?= escapeHtml($device['name']) ?>" aria-label="Назва девайса" required>
                            <button type="submit">Зберегти</button>
                        </form>
                    </td>
                    <td><code><?= escapeHtml($device['id']) ?></code></td>
                    <td><?= escapeHtml($status) ?></td>
                    <td>
                        <?php if ($lastUpdate): ?>
                            <time datetime="<?= escapeHtml($lastUpdate['datetime']) ?>">
                                <?= escapeHtml($lastUpdate['kyiv']) ?> <span class="muted">(Київ)</span><br>
                                <span class="muted"><?= escapeHtml($lastUpdate['utc']) ?></span>
                            </time>
                        <?php else: ?>
                            <?= escapeHtml($device['last_update'] ?? '—') ?>
                        <?php endif; ?>
                    </td>
                    <td>
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
            <?php if (!$devices): ?><tr><td colspan="5" class="muted">У базі поки немає девайсів.</td></tr><?php endif; ?>
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
            <button type="submit">Створити й згенерувати токен</button>
        </form>
    </div>

    <h2>Користувачі</h2>
    <div class="panel">
        <table>
            <thead><tr><th>ID</th><th>Облікові дані</th><th>Створено</th><th>Доступ до девайсів</th><th>API-токен</th><th>2FA</th></tr></thead>
            <tbody>
            <?php foreach ($users as $user): ?>
                <tr>
                    <td><?= (int) $user['id'] ?></td>
                    <td>
                        <form method="post">
                            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                            <input type="hidden" name="action" value="update_user">
                            <input type="hidden" name="user_id" value="<?= (int) $user['id'] ?>">
                            <label>Логін<br><input type="text" name="username" value="<?= escapeHtml($user['username']) ?>" maxlength="64" required></label><br>
                            <label>Роль<br>
                                <select name="role">
                                    <option value="user" <?= $user['role'] === 'user' ? 'selected' : '' ?>>user</option>
                                    <option value="admin" <?= $user['role'] === 'admin' ? 'selected' : '' ?>>admin</option>
                                </select>
                            </label><br>
                            <label>Новий пароль<br><input type="password" name="new_password" autocomplete="new-password"></label><br>
                            <button type="submit">Зберегти</button>
                        </form>
                    </td>
                    <td><?= escapeHtml($user['created_at'] ?? '—') ?></td>
                    <td>
                        <form method="post">
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
                    <td>
                        <form method="post" onsubmit="return confirm('Згенерувати новий API-токен? Попередній токен одразу перестане працювати.');">
                            <input type="hidden" name="csrf_token" value="<?= escapeHtml($csrfToken) ?>">
                            <input type="hidden" name="action" value="generate_api_token">
                            <input type="hidden" name="user_id" value="<?= (int) $user['id'] ?>">
                            <button type="submit">Згенерувати / перевипустити</button>
                        </form>
                    </td>
                    <td>
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
                            <button type="submit">Видалити користувача</button>
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
            <button type="submit">Створити користувача</button>
        </form>
        <p class="muted">Для нового користувача код згенерує секрет 2FA і покаже QR-код після створення.</p>
    </div>

    <script src="vendor/qrcode-generator.js"></script>
    <script>
        document.querySelectorAll('.totp-qr[data-otpauth]').forEach((element) => {
            const qr = qrcode(0, 'M');
            qr.addData(element.dataset.otpauth, 'Byte');
            qr.make();
            element.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
        });
    </script>
    <?php endif; ?>
</body>
</html>