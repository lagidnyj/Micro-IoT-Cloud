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

function postString(string $key): string
{
    $value = $_POST[$key] ?? '';
    if (!is_string($value)) {
        throw new InvalidArgumentException('Некоректні дані форми.');
    }

    return $value;
}

function setUserFlash(string $message, string $type = 'success'): void
{
    $_SESSION['user_flash'] = ['message' => $message, 'type' => $type];
}

function redirectToUserPanel(): void
{
    header('Location: index.php');
    exit;
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

    return [
        'datetime' => $utcTime->format(DateTime::ATOM),
        'kyiv' => $utcTime->setTimezone(new DateTimeZone('Europe/Kyiv'))->format('d.m.Y H:i:s'),
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

$now = time();
if (isset($_SESSION['user_pending_user_id'])
    && (!isset($_SESSION['user_pending_started']) || $now - (int) $_SESSION['user_pending_started'] > 300)
) {
    unset($_SESSION['user_pending_user_id'], $_SESSION['user_pending_started']);
    setUserFlash('Час входу вичерпано. Увійдіть знову.', 'error');
}

$authenticatedUser = null;
if (isset($_SESSION['user_user_id'])) {
    if (!isset($_SESSION['user_last_activity']) || $now - (int) $_SESSION['user_last_activity'] > 1800) {
        unset($_SESSION['user_user_id'], $_SESSION['user_last_activity'], $_SESSION['user_password_hash']);
        session_regenerate_id(true);
        $_SESSION['user_csrf'] = bin2hex(random_bytes(32));
        setUserFlash('Сесію завершено через бездіяльність. Увійдіть знову.', 'error');
    } else {
        $statement = $pdo->prepare("SELECT id, username, password_hash FROM users WHERE id = :id AND role = 'user'");
        $statement->execute([':id' => (int) $_SESSION['user_user_id']]);
        $authenticatedUser = $statement->fetch(PDO::FETCH_ASSOC);
        if (!$authenticatedUser
            || !isset($_SESSION['user_password_hash'])
            || !is_string($_SESSION['user_password_hash'])
            || !is_string($authenticatedUser['password_hash'])
            || !hash_equals($authenticatedUser['password_hash'], $_SESSION['user_password_hash'])
        ) {
            unset($_SESSION['user_user_id'], $_SESSION['user_last_activity'], $_SESSION['user_password_hash']);
            session_regenerate_id(true);
            $_SESSION['user_csrf'] = bin2hex(random_bytes(32));
            setUserFlash('Облікові дані змінилися або обліковий запис більше не має доступу. Увійдіть знову.', 'error');
        } else {
            $_SESSION['user_last_activity'] = $now;
        }
    }
}

if (!isset($_SESSION['user_csrf'])) {
    $_SESSION['user_csrf'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['user_csrf'];

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

    $statement = $pdo->prepare(
        'SELECT 1 FROM user_devices WHERE user_id = :user_id AND device_id = :device_id'
    );
    $statement->execute([':user_id' => (int) $authenticatedUser['id'], ':device_id' => $deviceId]);
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

    $state = json_decode($contents);
    if (json_last_error() !== JSON_ERROR_NONE || !is_object($state)) {
        error_log('Invalid JSON in device state file: ' . $filePath);
        http_response_code(500);
        exit('{"error":"Device state contains invalid JSON."}');
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

    try {
        $action = postString('action');
        if ($action === 'login_password') {
            if (!empty($_SESSION['user_login_locked_until']) && $now < (int) $_SESSION['user_login_locked_until']) {
                setUserFlash('Забагато невдалих спроб. Спробуйте пізніше.', 'error');
                redirectToUserPanel();
            }

            $username = trim(postString('username'));
            $password = postString('password');
            $statement = $pdo->prepare(
                "SELECT id, password_hash, totp_secret FROM users WHERE username = :username AND role = 'user'"
            );
            $statement->execute([':username' => $username]);
            $user = $statement->fetch(PDO::FETCH_ASSOC);

            if ($user
                && password_verify($password, $user['password_hash'])
                && is_string($user['totp_secret'])
                && $user['totp_secret'] !== ''
            ) {
                session_regenerate_id(true);
                $_SESSION['user_csrf'] = bin2hex(random_bytes(32));
                $_SESSION['user_pending_user_id'] = (int) $user['id'];
                $_SESSION['user_pending_started'] = $now;
                unset($_SESSION['user_flash']);
                unset($_SESSION['user_user_id'], $_SESSION['user_last_activity'], $_SESSION['user_password_hash']);
            } else {
                $failures = (int) ($_SESSION['user_login_failures'] ?? 0) + 1;
                $_SESSION['user_login_failures'] = $failures;
                if ($failures >= 5) {
                    $_SESSION['user_login_locked_until'] = $now + 300;
                    $_SESSION['user_login_failures'] = 0;
                }
                setUserFlash('Не вдалося увійти. Перевірте логін, пароль і налаштування 2FA.', 'error');
            }
            redirectToUserPanel();
        }

        if ($action === 'login_totp') {
            if (!empty($_SESSION['user_login_locked_until']) && $now < (int) $_SESSION['user_login_locked_until']) {
                setUserFlash('Забагато невдалих спроб. Спробуйте пізніше.', 'error');
                redirectToUserPanel();
            }

            $pendingUserId = (int) ($_SESSION['user_pending_user_id'] ?? 0);
            $pendingStarted = (int) ($_SESSION['user_pending_started'] ?? 0);
            if (!$pendingUserId || !$pendingStarted || $now - $pendingStarted > 300) {
                unset($_SESSION['user_pending_user_id'], $_SESSION['user_pending_started']);
                setUserFlash('Час входу вичерпано. Увійдіть знову.', 'error');
                redirectToUserPanel();
            }

            $statement = $pdo->prepare(
                "SELECT totp_secret, password_hash FROM users WHERE id = :id AND role = 'user'"
            );
            $statement->execute([':id' => $pendingUserId]);
            $user = $statement->fetch(PDO::FETCH_ASSOC);
            $code = postString('totp_code');
            if ($user && is_string($user['totp_secret']) && verifyTotpCode($user['totp_secret'], $code, $now)) {
                session_regenerate_id(true);
                $_SESSION['user_csrf'] = bin2hex(random_bytes(32));
                $_SESSION['user_user_id'] = $pendingUserId;
                $_SESSION['user_password_hash'] = $user['password_hash'];
                $_SESSION['user_last_activity'] = $now;
                unset(
                    $_SESSION['user_pending_user_id'],
                    $_SESSION['user_pending_started'],
                    $_SESSION['user_login_failures'],
                    $_SESSION['user_login_locked_until']
                );
                setUserFlash('Вхід виконано.');
            } else {
                $failures = (int) ($_SESSION['user_login_failures'] ?? 0) + 1;
                $_SESSION['user_login_failures'] = $failures;
                if ($failures >= 5) {
                    $_SESSION['user_login_locked_until'] = $now + 300;
                    $_SESSION['user_login_failures'] = 0;
                    unset($_SESSION['user_pending_user_id'], $_SESSION['user_pending_started']);
                    setUserFlash('Забагато невдалих спроб. Спробуйте знову через 5 хвилин.', 'error');
                } else {
                    setUserFlash('Невірний код автентифікатора.', 'error');
                }
            }
            redirectToUserPanel();
        }

        if ($action === 'cancel_login') {
            unset($_SESSION['user_pending_user_id'], $_SESSION['user_pending_started']);
            redirectToUserPanel();
        }

        if ($action === 'logout') {
            unset(
                $_SESSION['user_user_id'],
                $_SESSION['user_password_hash'],
                $_SESSION['user_last_activity'],
                $_SESSION['user_pending_user_id'],
                $_SESSION['user_pending_started']
            );
            session_regenerate_id(true);
            $_SESSION['user_csrf'] = bin2hex(random_bytes(32));
            setUserFlash('Ви вийшли з панелі.');
            redirectToUserPanel();
        }

        if (!$authenticatedUser) {
            http_response_code(403);
            exit('Authentication required.');
        }

        setUserFlash('Невідома дія.', 'error');
    } catch (InvalidArgumentException $error) {
        setUserFlash($error->getMessage(), 'error');
    }
    redirectToUserPanel();
}

$flash = $_SESSION['user_flash'] ?? null;
unset($_SESSION['user_flash']);
$devices = [];
if ($authenticatedUser) {
    $statement = $pdo->prepare(
        'SELECT d.id, d.name, d.last_payload, d.last_update, '
        . 'settings.enabled AS history_enabled, '
        . 'settings.interval_seconds AS history_interval_seconds, '
        . 'settings.retention_seconds AS history_retention_seconds '
        . 'FROM user_devices AS ud '
        . 'INNER JOIN devices AS d ON d.id = ud.device_id '
        . 'INNER JOIN device_history_settings AS settings ON settings.device_id = d.id '
        . 'WHERE ud.user_id = :user_id '
        . 'ORDER BY d.name, d.id'
    );
    $statement->execute([':user_id' => (int) $authenticatedUser['id']]);
    $devices = $statement->fetchAll(PDO::FETCH_ASSOC);
}
?>
<!doctype html>
<html lang="uk">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Панель користувача · Micro-IoT-Cloud</title>
    <link rel="stylesheet" href="style.css?v=<?= (int) @filemtime(__DIR__ . '/style.css') ?>">
    <script>try { if (localStorage.getItem('userView') === 'mobile') document.documentElement.classList.add('mobile'); } catch (e) {}</script>
</head>
<body>
    <header class="top">
        <h1>Панель користувача</h1>
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
        <button type="button" id="view-toggle" class="view-toggle"></button>
    </header>

    <?php if (!$authenticatedUser): ?>
        <section class="panel auth-panel">
            <?php if (is_array($flash)): ?>
                <div class="notice <?= escapeHtml($flash['type'] ?? '') ?>"><?= escapeHtml($flash['message'] ?? '') ?></div>
            <?php endif; ?>

            <?php if (isset($_SESSION['user_pending_user_id'])): ?>
                <h2>Підтвердження 2FA</h2>
                <p>Введіть шестизначний код із застосунку-автентифікатора.</p>
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
                <h2>Вхід користувача</h2>
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
        <div class="notice <?= escapeHtml($flash['type'] ?? '') ?>"><?= escapeHtml($flash['message'] ?? '') ?></div>
    <?php endif; ?>

    <h2>Ваші девайси</h2>
    <div class="panel">
        <table class="devices user-devices">
            <thead><tr><th>Назва</th><th>device_id</th><th>Стан пристрою</th><th>Стан зв'язку</th><th>Останній зв'язок</th><th>Історія</th><th>Дані</th></tr></thead>
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
                ?>
                <tr>
                    <td data-label="Назва"><?= escapeHtml($device['name']) ?></td>
                    <td data-label="device_id"><code><?= escapeHtml($device['id']) ?></code></td>
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
                            <time datetime="<?= escapeHtml($lastUpdate['datetime']) ?>"><?= escapeHtml($lastUpdate['kyiv']) ?></time>
                            <div class="muted"><?= escapeHtml($lastUpdate['utc']) ?></div>
                        <?php else: ?>
                            <span class="muted">Немає даних</span>
                        <?php endif; ?>
                    </td>
                    <td data-label="Історія"><?= escapeHtml(deviceHistoryLabel([
                        'enabled' => $device['history_enabled'],
                        'interval_seconds' => $device['history_interval_seconds'],
                        'retention_seconds' => $device['history_retention_seconds'],
                    ])) ?></td>
                    <td data-label="Дані">
                        <a href="index.php?device_json=<?= rawurlencode((string) $device['id']) ?>">Відкрити JSON</a>
                    </td>
                </tr>
            <?php endforeach; ?>
            <?php if (!$devices): ?><tr><td colspan="7" class="muted">Вам поки не призначено жодного девайса. Зверніться до адміністратора.</td></tr><?php endif; ?>
            </tbody>
        </table>
    </div>
    <p class="muted">Стан не оновлюється автоматично. Перезавантажте сторінку, щоб побачити актуальні дані.</p>
    <?php endif; ?>

    <script>
        (function () {
            const root = document.documentElement;
            const button = document.getElementById('view-toggle');
            const sync = () => { button.textContent = root.classList.contains('mobile') ? 'Вигляд для ПК' : 'Вигляд для телефона'; };
            button.addEventListener('click', () => {
                const mobile = root.classList.toggle('mobile');
                try { localStorage.setItem('userView', mobile ? 'mobile' : 'desktop'); } catch (e) {}
                sync();
            });
            sync();
        })();
    </script>
</body>
</html>
