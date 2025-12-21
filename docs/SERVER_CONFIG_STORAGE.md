# Зберігання конфігурації серверів

## База даних

Конфігурація серверів зберігається в **PostgreSQL** в таблиці `servers` бази даних `core`.

## Структура таблиці

```sql
CREATE TABLE servers (
    id SERIAL PRIMARY KEY,
    server_ip VARCHAR(45) NOT NULL UNIQUE,        -- IP адреса сервера (IPv4 або IPv6)
    server_port INTEGER NOT NULL DEFAULT 22,      -- SSH порт для підключення (зазвичай 22)
    ssh_port INTEGER NOT NULL,                    -- SSH порт після налаштування (55000-56000)
    hostname VARCHAR(255),                        -- Hostname сервера (опціонально, для довідки)
    setup_date TIMESTAMP WITH TIME ZONE,          -- Дата першого налаштування
    created_at TIMESTAMP WITH TIME ZONE,          -- Час створення запису
    updated_at TIMESTAMP WITH TIME ZONE           -- Час останнього оновлення
);
```

## Зберігаються дані

✅ **Зберігаються:**
- `server_ip` - IP адреса сервера (уникальний ідентифікатор)
- `server_port` - SSH порт для підключення (зазвичай 22)
- `ssh_port` - SSH порт, налаштований на сервері після setup (динамічно згенерований в діапазоні 55000-56000)
- `hostname` - Hostname сервера (опціонально, отримується з сервера)
- `setup_date` - Дата першого налаштування
- `created_at`, `updated_at` - Timestamps

❌ **НЕ зберігаються (з міркувань безпеки):**
- `username` - Ім'я користувача для SSH підключення
- `password` - Пароль для SSH підключення

## Процес зберігання

### 1. Завантаження конфігурації (loadServerConfig)

Перед початком setup, система намагається завантажити існуючу конфігурацію з бази даних:

```go
// Завантажується конфігурація для server_ip
query := `SELECT server_port, ssh_port, hostname FROM servers WHERE server_ip = $1`
```

Якщо конфігурація знайдена:
- Використовується наявний `ssh_port` (якщо він вже був згенерований раніше)
- Завантажуються інші параметри

Якщо конфігурація не знайдена:
- Генерується новий `ssh_port`
- Створюється новий запис в базі даних

### 2. Збереження конфігурації (saveServerConfig)

Після завершення setup, конфігурація зберігається в базу даних:

```go
// Upsert конфігурації (оновлення якщо існує, вставка якщо ні)
INSERT INTO servers (server_ip, server_port, ssh_port, hostname, ...)
VALUES ($1, $2, $3, $4, ...)
ON CONFLICT (server_ip) DO UPDATE SET ...
```

**Важливо:**
- `server_ip` використовується як унікальний ідентифікатор
- `hostname` отримується з віддаленого сервера через SSH команду `hostname`
- `username` та `password` НЕ зберігаються

## Структура даних в коді

```go
type ServerConfig struct {
    ServerIP   string `json:"server_ip"`   // IP адреса сервера
    ServerPort int    `json:"server_port"` // SSH порт для підключення
    SSHPort    int    `json:"ssh_port"`    // SSH порт після налаштування
    Hostname   string `json:"hostname"`    // Hostname сервера
}
```

## Безпека

1. **Паролі не зберігаються** - використовуються тільки для SSH підключення під час setup
2. **IP як ідентифікатор** - замість hostname (hostname може змінюватися)
3. **Шифрування** - всі дані зберігаються в PostgreSQL з можливістю шифрування на рівні БД

## Приклад використання

```go
// Setup server з IP 192.168.1.37, порт 22
setup.SetupServer("192.168.1.37", 22, "maksym", "password123")

// В базу даних збережеться:
// - server_ip: "192.168.1.37"
// - server_port: 22
// - ssh_port: 55234 (згенерований в діапазоні 55000-56000)
// - hostname: "ubuntu-server" (отриманий з сервера)
// username та password НЕ зберігаються
```

## Міграція даних

Якщо потрібно додати нові поля до таблиці, використовуйте SQL міграції:

```sql
-- Приклад додавання нового поля
ALTER TABLE servers ADD COLUMN IF NOT EXISTS new_field VARCHAR(255);
```
