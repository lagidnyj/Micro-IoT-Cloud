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
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');

require __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../includes/totp.php';

function registrationEscape($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function registrationPostString(string $key): string
{
    $value = $_POST[$key] ?? '';
    if (!is_string($value)) {
        throw new InvalidArgumentException('Некоректні дані форми.');
    }

    return $value;
}

function registrationTotpUri(string $username, string $secret): string
{
    return 'otpauth://totp/' . rawurlencode('Micro-IoT-Cloud:' . $username)
        . '?' . http_build_query([
            'secret' => $secret,
            'issuer' => 'Micro-IoT-Cloud',
            'algorithm' => 'SHA1',
            'digits' => 6,
            'period' => 30,
        ]);
}

if (!isset($_SESSION['registration_csrf'])) {
    $_SESSION['registration_csrf'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['registration_csrf'];
$now = time();
$formError = null;
$pending = $_SESSION['registration_pending'] ?? null;

if (is_array($pending)
    && (!isset($pending['started_at']) || $now - (int) $pending['started_at'] > 600)
) {
    unset($_SESSION['registration_pending']);
    $pending = null;
    $formError = 'Час реєстрації вичерпано. Відкрийте запрошення ще раз.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedCsrf = $_POST['csrf_token'] ?? '';
    if (!is_string($submittedCsrf) || !hash_equals($csrfToken, $submittedCsrf)) {
        http_response_code(400);
        exit('Invalid request token.');
    }

    try {
        $action = registrationPostString('action');
        if ($action === 'start') {
            $inviteToken = registrationPostString('invite_token');
            if (!preg_match('/\A[a-f0-9]{64}\z/', $inviteToken)) {
                throw new InvalidArgumentException('Запрошення недійсне, використане або прострочене.');
            }

            $inviteHash = hash('sha256', $inviteToken);
            $inviteStatement = $pdo->prepare(
                'SELECT 1 FROM user_invites '
                . 'WHERE token_hash = :token_hash AND used_at IS NULL AND expires_at > :now'
            );
            $inviteStatement->execute([':token_hash' => $inviteHash, ':now' => $now]);
            if ($inviteStatement->fetchColumn() === false) {
                throw new InvalidArgumentException('Запрошення недійсне, використане або прострочене.');
            }

            $username = trim(registrationPostString('username'));
            $password = registrationPostString('password');
            if ($username === '' || strlen($username) > 64) {
                throw new InvalidArgumentException('Логін має містити від 1 до 64 байтів.');
            }
            if (strlen($password) < 12 || strlen($password) > 72) {
                throw new InvalidArgumentException('Пароль має містити від 12 до 72 байтів.');
            }

            $usernameStatement = $pdo->prepare('SELECT 1 FROM users WHERE username = :username');
            $usernameStatement->execute([':username' => $username]);
            if ($usernameStatement->fetchColumn() !== false) {
                throw new InvalidArgumentException('Цей логін уже зайнятий.');
            }

            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            if ($passwordHash === false) {
                throw new RuntimeException('Не вдалося захешувати пароль.');
            }

            $totpSecret = createTotpSecret();
            session_regenerate_id(true);
            $_SESSION['registration_csrf'] = bin2hex(random_bytes(32));
            $csrfToken = $_SESSION['registration_csrf'];
            $_SESSION['registration_pending'] = [
                'invite_hash' => $inviteHash,
                'username' => $username,
                'password_hash' => $passwordHash,
                'totp_secret' => $totpSecret,
                'started_at' => $now,
                'attempts' => 0,
            ];
            $pending = $_SESSION['registration_pending'];
            $formError = null;
        } elseif ($action === 'complete') {
            $pending = $_SESSION['registration_pending'] ?? null;
            if (!is_array($pending)
                || !isset(
                    $pending['invite_hash'],
                    $pending['username'],
                    $pending['password_hash'],
                    $pending['totp_secret'],
                    $pending['started_at']
                )
                || $now - (int) $pending['started_at'] > 600
            ) {
                unset($_SESSION['registration_pending']);
                $pending = null;
                throw new InvalidArgumentException('Час реєстрації вичерпано. Відкрийте запрошення ще раз.');
            }

            $code = registrationPostString('totp_code');
            if (!verifyTotpCode((string) $pending['totp_secret'], $code, $now)) {
                $pending['attempts'] = (int) ($pending['attempts'] ?? 0) + 1;
                if ($pending['attempts'] >= 5) {
                    unset($_SESSION['registration_pending']);
                    $pending = null;
                    throw new InvalidArgumentException('Забагато невдалих кодів. Почніть реєстрацію за запрошенням знову.');
                }
                $_SESSION['registration_pending'] = $pending;
                throw new InvalidArgumentException('Код автентифікатора неправильний. Спробуйте ще раз.');
            }

            $pdo->beginTransaction();
            $insertUser = $pdo->prepare(
                "INSERT INTO users (username, password_hash, totp_secret, role) "
                . "VALUES (:username, :password_hash, :totp_secret, 'user')"
            );
            $insertUser->execute([
                ':username' => $pending['username'],
                ':password_hash' => $pending['password_hash'],
                ':totp_secret' => $pending['totp_secret'],
            ]);
            $userId = (int) $pdo->lastInsertId();

            $redeemInvite = $pdo->prepare(
                'UPDATE user_invites SET used_at = CURRENT_TIMESTAMP, used_by = :user_id '
                . 'WHERE token_hash = :token_hash AND used_at IS NULL AND expires_at > :now'
            );
            $redeemInvite->execute([
                ':user_id' => $userId,
                ':token_hash' => $pending['invite_hash'],
                ':now' => $now,
            ]);
            if ($redeemInvite->rowCount() !== 1) {
                $pdo->rollBack();
                unset($_SESSION['registration_pending']);
                throw new InvalidArgumentException('Запрошення вже використане, відкликане або прострочене.');
            }

            $pdo->commit();
            unset($_SESSION['registration_pending']);
            session_regenerate_id(true);
            unset($_SESSION['registration_csrf']);
            $_SESSION['user_flash'] = [
                'message' => 'Реєстрацію завершено. Тепер увійдіть із логіном, паролем і кодом 2FA.',
                'type' => 'success',
            ];
            header('Location: index.php');
            exit;
        } else {
            throw new InvalidArgumentException('Невідома дія.');
        }
    } catch (InvalidArgumentException $error) {
        $formError = $error->getMessage();
        $pending = $_SESSION['registration_pending'] ?? null;
    } catch (PDOException $error) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('User registration database operation failed: ' . $error->getMessage());
        unset($_SESSION['registration_pending']);
        $pending = null;
        $formError = 'Не вдалося завершити реєстрацію. Перевірте, чи логін не зайнятий, і почніть знову за запрошенням.';
    }
}

$inviteToken = $_GET['invite'] ?? '';
$inviteHash = is_string($inviteToken) && preg_match('/\A[a-f0-9]{64}\z/', $inviteToken)
    ? hash('sha256', $inviteToken)
    : '';
$inviteValid = false;
if ($inviteHash !== '') {
    $inviteStatement = $pdo->prepare(
        'SELECT 1 FROM user_invites '
        . 'WHERE token_hash = :token_hash AND used_at IS NULL AND expires_at > :now'
    );
    $inviteStatement->execute([':token_hash' => $inviteHash, ':now' => time()]);
    $inviteValid = $inviteStatement->fetchColumn() !== false;
}

if (is_array($pending)) {
    $pendingInviteStatement = $pdo->prepare(
        'SELECT 1 FROM user_invites '
        . 'WHERE token_hash = :token_hash AND used_at IS NULL AND expires_at > :now'
    );
    $pendingInviteStatement->execute([
        ':token_hash' => $pending['invite_hash'],
        ':now' => time(),
    ]);
    if ($pendingInviteStatement->fetchColumn() === false) {
        unset($_SESSION['registration_pending']);
        $pending = null;
        $formError = 'Запрошення вже використане, відкликане або прострочене.';
    }
}
?>
<!doctype html>
<html lang="uk">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Реєстрація · Micro-IoT-Cloud</title>
    <link rel="stylesheet" href="style.css?v=<?= (int) @filemtime(__DIR__ . '/style.css') ?>">
    <script>try { if (localStorage.getItem('userView') === 'mobile') document.documentElement.classList.add('mobile'); } catch (e) {}</script>
</head>
<body>
    <header class="top">
        <h1>Реєстрація користувача</h1>
        <a class="help-link" href="index.php">До входу</a>
        <button type="button" id="view-toggle" class="view-toggle"></button>
    </header>

    <section class="panel auth-panel">
        <?php if ($formError !== null): ?>
            <div class="notice error"><?= registrationEscape($formError) ?></div>
        <?php endif; ?>

        <?php if (is_array($pending)): ?>
            <h2>Налаштування 2FA</h2>
            <p>Відскануйте QR-код у застосунку-автентифікаторі, потім введіть згенерований шестизначний код.</p>
            <div class="totp-qr" data-otpauth="<?= registrationEscape(registrationTotpUri($pending['username'], $pending['totp_secret'])) ?>"></div>
            <p>Якщо QR-код недоступний, введіть ключ вручну: <code><?= registrationEscape($pending['totp_secret']) ?></code></p>
            <p class="muted">Після підтвердження коду запрошення буде використане, а обліковий запис створено.</p>
            <form method="post" class="stack">
                <input type="hidden" name="csrf_token" value="<?= registrationEscape($csrfToken) ?>">
                <input type="hidden" name="action" value="complete">
                <label>Код автентифікатора
                    <input type="text" name="totp_code" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" maxlength="6" required autofocus>
                </label>
                <button type="submit" class="primary">Підтвердити та створити акаунт</button>
            </form>
        <?php elseif ($inviteValid): ?>
            <h2>Створення акаунта</h2>
            <p>Запрошення дійсне. Створіть логін і пароль, а на наступному кроці налаштуйте 2FA.</p>
            <form method="post" class="stack">
                <input type="hidden" name="csrf_token" value="<?= registrationEscape($csrfToken) ?>">
                <input type="hidden" name="action" value="start">
                <input type="hidden" name="invite_token" value="<?= registrationEscape($inviteToken) ?>">
                <label>Логін
                    <input type="text" name="username" autocomplete="username" maxlength="64" required autofocus>
                </label>
                <label>Пароль (12–72 байти)
                    <input type="password" name="password" autocomplete="new-password" minlength="12" maxlength="72" required>
                </label>
                <button type="submit" class="primary">Продовжити</button>
            </form>
        <?php else: ?>
            <h2>Запрошення недійсне</h2>
            <p>Посилання відсутнє, уже використане, відкликане або прострочене. Попросіть адміністратора надіслати нове.</p>
        <?php endif; ?>
    </section>

    <?php if (is_array($pending)): ?>
        <script src="../adminpanel/vendor/qrcode-generator.js"></script>
        <script>
            document.querySelectorAll('.totp-qr[data-otpauth]').forEach((element) => {
                const qr = qrcode(0, 'M');
                qr.addData(element.dataset.otpauth, 'Byte');
                qr.make();
                element.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
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
                try { localStorage.setItem('userView', mobile ? 'mobile' : 'desktop'); } catch (e) {}
                sync();
            });
            sync();
        })();
    </script>
</body>
</html>
