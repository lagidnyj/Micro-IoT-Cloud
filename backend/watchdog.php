<?php
$projectDir = dirname(__DIR__);
$storageDir = $projectDir . '/storage/';
$rulesFile = $projectDir . '/rules.json';
$statesFile = $projectDir . '/states.json'; // Файл для збереження історії спрацювань
$telegramBotToken = 'ТВІЙ_BOT_TOKEN';

// Час кулдауну в секундах (наприклад, 1 година = 3600 секунд)
$cooldownTime = 3600; 

if (!file_exists($rulesFile)) {
    exit("Rules file not found.");
}

$rules = json_decode(file_get_contents($rulesFile), true);
if (!is_array($rules)) {
    exit("Rules file contains invalid JSON.");
}

// Завантажуємо попередні стани (якщо файл існує)
$states = file_exists($statesFile) ? json_decode(file_get_contents($statesFile), true) : [];
if (!is_array($states)) {
    $states = [];
}
$stateChanged = false;

foreach ($rules as $index => $rule) {
    if (!is_array($rule)
        || !isset($rule['device'], $rule['param'], $rule['operator'], $rule['chat_id'], $rule['message'])
        || !array_key_exists('threshold', $rule)
        || !preg_match('/\A[a-zA-Z0-9_-]+\z/', $rule['device'])
        || !is_string($rule['param'])
    ) {
        continue;
    }

    // Унікальний ключ для правила (на основі індексу або назви пристрою+параметра)
    $ruleKey = $rule['device'] . '_' . $rule['param'] . '_' . md5(json_encode($rule));
    
    $filePath = $storageDir . $rule['device'] . '.json';
    if (!file_exists($filePath)) {
        continue;
    }
    
    $data = json_decode(file_get_contents($filePath), true);
    if (!is_array($data) || !getNestedValue($data, $rule['param'], $currentVal)) {
        continue;
    }
    
    // Перевірка поточного стану умови
    $isTriggered = false;
    switch ($rule['operator']) {
        case '<=':
            $isTriggered = is_numeric($currentVal) && is_numeric($rule['threshold'])
                && (float) $currentVal <= (float) $rule['threshold'];
            break;
        case '>=':
            $isTriggered = is_numeric($currentVal) && is_numeric($rule['threshold'])
                && (float) $currentVal >= (float) $rule['threshold'];
            break;
        case '==': $isTriggered = $currentVal === $rule['threshold']; break;
        case '!=': $isTriggered = $currentVal !== $rule['threshold']; break;
    }
    
    // Отримуємо попередній стан для цього правила
    $lastState = $states[$ruleKey] ?? ['triggered' => false, 'last_sent' => 0];
    $now = time();
    
    // ЛОГІКА СПОВІЩЕННЯ:
    // Сповіщаємо, ЯКЩО:
    // 1. Умова виконується ЗАРАЗ ($isTriggered === true)
    // І при цьому виконується хоча б одна з умов антиспаму:
    //    А) Це новий перехід у стан тривоги ($lastState['triggered'] === false)
    //    Б) Пройшов час кулдауну з моменту останнього сповіщення ($now - $lastState['last_sent'] > $cooldownTime)

    if ($isTriggered) {
        $isNewTrigger = ($lastState['triggered'] === false);
        $cooldownExpired = ($now - $lastState['last_sent'] > $cooldownTime);
        
        if ($isNewTrigger || $cooldownExpired) {
            // Формуємо і відправляємо повідомлення
            $displayValue = is_bool($currentVal) ? ($currentVal ? 'true' : 'false') : (string) $currentVal;
            $msgText = str_replace('{value}', $displayValue, $rule['message']);
            sendTelegram($telegramBotToken, $rule['chat_id'], $msgText);
            
            // Оновлюємо стан
            $states[$ruleKey] = [
                'triggered' => true,
                'last_sent' => $now
            ];
            $stateChanged = true;
        }
    } else {
        // Якщо умова більше НЕ виконується (все повернулось в норму), 
        // скидаємо статус triggered, щоб при наступному падінні сповіщення прийшло миттєво.
        if ($lastState['triggered'] === true) {
            $states[$ruleKey] = [
                'triggered' => false,
                'last_sent' => $lastState['last_sent']
            ];
            $stateChanged = true;
            
            // Опціонально: можна слати сповіщення "Все окей, живлення відновлено"
            // sendTelegram($telegramBotToken, $rule['chat_id'], "✅ Статус нормалізувався: {$rule['param']} = {$currentVal}");
        }
    }
}

// Зберігаємо оновлені стани у файл, якщо були зміни
if ($stateChanged) {
    file_put_contents($statesFile, json_encode($states, JSON_PRETTY_PRINT));
}

function sendTelegram($token, $chatId, $text) {
    $url = "https://api.telegram.org/bot{$token}/sendMessage";
    $data = ['chat_id' => $chatId, 'text' => $text, 'parse_mode' => 'Markdown'];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_exec($ch);
    curl_close($ch);
}

function getNestedValue(array $data, string $path, &$value): bool {
    $value = $data;
    foreach (explode('.', $path) as $segment) {
        if (!is_array($value) || !array_key_exists($segment, $value)) {
            return false;
        }
        $value = $value[$segment];
    }
    return true;
}
