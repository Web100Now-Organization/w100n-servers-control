<!-- c1064373-e8e8-4797-b002-da77f2c9c4b4 4c9c6015-0fe4-4e60-b776-5007c32ffd0e -->
# Архітектура гібридної інфраструктури w100n_core

## Концепція

Гібридна архітектура: **DigitalOcean (Primary - основне навантаження + Databases)** + **Contabo Dedicated (Scaling для пікового навантаження)** + **Cloudflare (DNS)** + **CDN для медіа** з автоматичним масштабуванням.

**Чому DigitalOcean Primary:**
- **99.99% Uptime SLA** (гарантовано)
- **Managed Databases** - стабільніші, автоматичні бекапи, high availability
- **Простота автоматизації** - DO API для автоматичного масштабування
- **Стабільність інфраструктури** - redundant storage, автоматичне відновлення
- **DDoS захист** вбудований
- **Географічне розподілення** - легко масштабувати в різні регіони
- **Cloudflare для DNS** - стабільний DNS з динамічним перенаправленням
- **CDN для відео/фото** - окремий потужний CDN для медіа контенту (мікросервіс відео меню)

**Contabo для пікового навантаження:**
- **Потужні сервери:** 32 cores, 128GB RAM, 2x1TB NVMe, 10 Gbit/s
- **Економія:** $224/міс за потужний сервер (дешевше ніж масштабувати багато DO Droplets)
- **Висока продуктивність** для обробки пікового трафіку
- **Великий обсяг RAM** для кешування та обробки даних
- **10 Gbit/s порт** для швидкої передачі даних
- **Автоматичне масштабування** - активується при піковому навантаженні на DO
- Використовується як scaling сервер коли DO Droplets не справляються з навантаженням

## Економіка та стабільність

### Економія

**DigitalOcean (Primary - основне навантаження + Databases):**
- **Managed PostgreSQL:** 2 vCPU / 4GB RAM = **$60/міс** (Primary)
- **Managed MongoDB:** 2 vCPU / 4GB RAM = **$60/міс** (Primary)
- **DO Droplet 1:** 4 vCPU / 8GB RAM = **$48/міс** (w100n_core Primary)
- **DO Droplet 2:** 4 vCPU / 8GB RAM = **$48/міс** (Frontend Primary)
- **DO Droplet 3:** 2 vCPU / 4GB RAM = **$24/міс** (Go Control Panel + Monitoring)
- **Разом DO Primary: ~$293/міс** (з Managed DB, 3 Droplets) або **~$341/міс** (4 Droplets)

**Contabo Dedicated (Scaling для пікового навантаження):**
- **Сервер 1:** 32 cores, 128GB RAM, 2x1TB NVMe, 10 Gbit/s = **$224/міс**
  - w100n_core + плагіни (мікросервіси) - активується при піковому навантаженні
  - Відео меню мікросервіс (обробка відео)
  - Next.js фронтенди
  - Redis для кешування
  - Nginx для reverse proxy
- **Разом Contabo: $0-448/міс** (залежить від навантаження, може бути вимкнений)

**Cloudflare (DNS + CDN):**
- **DNS:** Безкоштовно (Pro план $20/міс для додаткових функцій)
- **CDN для статики:** Безкоштовно (до 100GB/міс)
- **Cloudflare Stream (відео):** ~$1/1000 хвилин перегляду
- **Cloudflare R2 (storage):** $0.015/GB storage + $0.36/GB egress
- Або **BunnyCDN** (дешевше для великих обсягів): $0.01/GB storage + $0.01-0.05/GB bandwidth
- **Орієнтовно CDN: $50-200/міс** (залежить від трафіку відео/фото)

**Загальна вартість:**
- **Мінімальна (без Contabo):** $293 (DO Primary) + $50 (CDN) = **~$343/міс**
- **З Contabo для scaling:** $293 (DO Primary) + $224 (Contabo) + $100 (CDN) = **~$617/міс**
- **Рекомендована (DO + Contabo):** $341 (DO, 4 Droplets) + $224 (Contabo) + $100 (CDN) = **~$665/міс**

**Порівняння з повністю DigitalOcean (без Contabo для scaling):**
- Для високого навантаження потрібно більше Droplets (10-15+)
- Вартість: ~$600-1000/міс
- **Економія з Contabo scaling: $307-657/міс** (коли Contabo активний для пікового навантаження)
- **Без Contabo:** $343/міс (мінімальна конфігурація) - економніше ніж повністю DO при високому навантаженні

**Переваги DigitalOcean Primary:**
- 99.99% Uptime SLA (гарантовано)
- Managed Databases - стабільніші, автоматичне управління
- Простота автоматизації через DO API
- Легше масштабувати поступово (додавати Droplets при потребі)

**Переваги Contabo для Scaling:**
- Більше потужності за меншу ціну (коли потрібно)
- 128GB RAM vs 8GB на DO Droplet
- 32 cores vs 4 vCPU на DO Droplet
- 10 Gbit/s порт для швидкої передачі
- Ідеально для обробки пікового навантаження замість масштабування багатьох DO Droplets

**Додаткові переваги:**
- Автоматичне масштабування (DO → Contabo при піковому навантаженні)
- Оптимальна вартість при середньому навантаженні (тільки DO)

### Стабільність

**DigitalOcean (Primary):**
- **99.99% Uptime SLA** (гарантовано)
- Managed Databases з автоматичними бекапами
- Redundant storage (реплікація на рівні інфраструктури)
- DDoS захист (вбудований)
- Автоматичне відновлення при збоях
- Стабільна інфраструктура для основного навантаження
- Простота масштабування через DO API

**Contabo Dedicated (Scaling):**
- Потужна інфраструктура для пікового навантаження
- Висока продуктивність (32 cores, 128GB RAM)
- 10 Gbit/s порт для швидкої передачі
- Ідеально для обробки великого трафіку при пікових навантаженнях
- Може бути вимкнений коли навантаження низьке (економія)
- Автоматична активація при високому навантаженні

**Cloudflare (DNS + CDN):**
- Стабільний DNS з глобальною мережею
- DDoS захист на рівні DNS
- Автоматичне перенаправлення трафіку
- Load balancing між DO та Contabo
- Кешування на edge locations

**CDN (Cloudflare/BunnyCDN):**
- Глобальна мережа edge серверів
- Швидка доставка відео/фото по всьому світу
- DDoS захист
- Кешування на edge locations
- Автоматичне масштабування

**Гібридна архітектура:**
- **Стабільна основа**: DO Primary з 99.99% SLA
- **Бази даних на DO** - Managed Databases з автоматичним управлінням
- **Автоматичне масштабування**: DO → Contabo при піковому навантаженні
- **Zero data loss**: WAL/Oplog реплікація в Managed Databases
- Географічне розподілення (DO + Contabo в різних локаціях)
- **CDN для медіа** - окрема потужна інфраструктура
- Оптимальна вартість (Contabo використовується тільки при потребі)

**Результат:**
- **99.99%+ uptime** (DO гарантує SLA)
- Мінімальний downtime при проблемах
- Автоматичне відновлення
- Автоматичне масштабування при піковому навантаженні
- Оптимальна вартість (платиш за Contabo тільки коли потрібно)
- Швидка доставка медіа контенту через CDN

## Динамічне масштабування та синхронізація

### Масштабування

**На DigitalOcean (Primary):**
- Основні Droplets обробляють стандартне навантаження
- 4-8GB RAM достатньо для більшості сценаріїв
- 4 vCPU для паралельної обробки
- При збільшенні навантаження → додати більше DO Droplets або активувати Contabo
- Managed Databases автоматично масштабуються через DO API

**На Contabo Dedicated (Scaling для пікового навантаження):**
- Потужні сервери активуються при піковому навантаженні
- 128GB RAM для обробки великого обсягу даних
- 32 cores для паралельної обробки
- Автоматична активація коли DO Droplets не справляються
- Може бути вимкнений коли навантаження нормалізується (економія)
- При дуже високому навантаженні → додати другий Contabo сервер

**CDN автоматичне масштабування:**
- Cloudflare/BunnyCDN автоматично масштабуються
- Edge сервери по всьому світу
- Автоматичне кешування популярного контенту

**Приклади сценаріїв:**
```go
// Моніторинг навантаження на DO Primary
if doServers.AvgCPU > 80% && doServers.AvgRAM > 90% {
    // Автоматична активація Contabo для scaling
    contaboAPI.ActivateScalingServer()
    // Оновлення Cloudflare DNS для load balancing
    cloudflareAPI.UpdateDNS()
    // Перенаправлення частини трафіку на Contabo
}

// Scaling down коли навантаження знижується
if doServers.AvgCPU < 40% && doServers.AvgRAM < 50% && contaboServer.IsActive() {
    // Вимкнути Contabo (економія)
    contaboAPI.DeactivateScalingServer()
    // Повернути весь трафік на DO
    cloudflareAPI.UpdateDNS()
}

// Failover при проблемах на DO
if !doServers.IsHealthy() {
    // Автоматична активація Contabo як failover
    contaboAPI.ActivateScalingServer()
    // Оновлення Cloudflare DNS
    cloudflareAPI.UpdateDNS()
}
```

### Синхронізація DigitalOcean ↔ Contabo

**Що синхронізується:**
1. **Конфігурації баз даних** (connection info без паролів - паролі в Vault)
2. **Код та плагіни** (Git синхронізація)
3. **Environment variables** (non-sensitive .env файли - секрети в Vault)
4. **Docker images** (синхронізація контейнерів)
5. **Nginx конфігурації** (для фронтендів)
6. **SSL сертифікати** (private keys в Vault, автоматичне оновлення)
7. **Медіа файли** (синхронізація на CDN)

**Як працює:**
- Go Control Panel на DO Droplet 3 - центральний оркестратор
- DO Primary - джерело істини для конфігурацій
- При змінах на DO → автоматично синхронізує на Contabo (коли активний)
- При активації Contabo для scaling → синхронізує всі конфігурації з DO
- Webhook або polling кожні 30 секунд
- **CDN синхронізація:** автоматичне завантаження нових відео/фото на CDN

**Синхронізація через Git:**
```bash
# На DO Primary (джерело істини)
git push origin main

# Go Control Panel автоматично:
# 1. Pull на всіх DO Droplets (Primary)
# 2. Pull на Contabo сервер (якщо активний для scaling)
# 3. Перезапускає сервіси
# 4. Перевіряє health
# 5. Синхронізує медіа на CDN (якщо є нові файли)

# При активації Contabo для scaling:
# 1. Синхронізує код з Git (latest)
# 2. Синхронізує конфігурації з DO
# 3. Синхронізує non-sensitive environment variables (.env)
# 4. Налаштує доступ до Vault (той самий Vault на DO Droplet 3)
# 5. Запускає сервіси (секрети отримуються з Vault при старті)
# 6. Перевіряє health
```

### Динамічне змінювання конфігурацій

**Connection Manager (Go сервіс):**
- Централізоване управління connection strings
- Автоматичне оновлення при scaling (DO → Contabo)
- Для Managed Databases connection strings статичні (не змінюються при scaling)
- Hot reload без перезапуску сервісів
- Синхронізація з усіма мікросервісами
- Управління підключеннями до Managed Databases

**Cloudflare DNS Management:**
- Динамічне перенаправлення трафіку
- Health checks для автоматичного переключення
- Load balancing між DO (Primary) та Contabo (Scaling)
- Автоматичне перенаправлення при активації Contabo для scaling

**Приклад:**
```go
// Connection Manager API
POST /api/config/update
{
  "postgres_host": "managed-postgres-do.internal:25060",
  "mongo_host": "managed-mongo-do.internal:27017"
}

// Автоматично:
// 1. Оновлює конфігурацію на DO Droplets (Primary)
// 2. Синхронізує на Contabo сервер (якщо активний для scaling)
// 3. Перезапускає w100n_core з новими налаштуваннями
// 4. Перевіряє підключення
// 5. Оновлює Cloudflare DNS при scaling (load balancing DO ↔ Contabo)
```

## Компоненти

### 1. DigitalOcean (Primary - основне навантаження + Databases)

**DO Managed PostgreSQL:**
- 2 vCPU / 4GB RAM
- Автоматичні бекапи
- High availability
- **$60/міс**

**DO Managed MongoDB:**
- 2 vCPU / 4GB RAM
- ReplicaSet з автоматичним failover
- Автоматичні бекапи
- **$60/міс**

**DO Droplet 1: Application Primary**

- w100n_core (Go) + плагіни (мікросервіси) - основний сервер
- Відео меню мікросервіс (обробка відео)
- Redis для кешування
- PM2 для процесів
- Docker для контейнерів
- Nginx для reverse proxy
- 4 vCPU / 8GB RAM
- **$48/міс**

**DO Droplet 2: Frontend Primary**

- Next.js фронтенди (builder, адмін, вебсайти) - основний сервер
- Nginx для reverse proxy
- PM2 для процесів
- 4 vCPU / 8GB RAM
- **$48/міс**

**DO Droplet 3: Go Control Panel (Orchestrator)**

- Health checks (кожні 30 сек)
- Автоматичне масштабування (DO → Contabo при піковому навантаженні)
- Реплікація моніторинг
- Cloudflare DNS управління
- Алерти (Email/Slack)
- **Connection Manager** (централізоване управління БД)
- **Синхронізація конфігурацій** (DO → Contabo)
- **DigitalOcean API інтеграція** (автоматизація scaling)
- **Cloudflare API інтеграція** (DNS management, load balancing)
- **HashiCorp Vault** (Secrets Management - паролі БД, API ключі, SSL сертифікати)
- Monitoring (Loki, Prometheus, Grafana)
- 2 vCPU / 4GB RAM
- **$24/міс**

**DO Droplet 4 (опціонально): Additional Services**

- Додаткові мікросервіси
- Додаткове навантаження
- 4 vCPU / 8GB RAM
- **$48/міс**

### 2. Contabo Dedicated (Scaling для пікового навантаження)

**Contabo Server 1: Scaling Application Server**

**Характеристики:**
- 32 cores (AMD EPYC 9355P)
- 128GB RAM
- 2x 1TB NVMe SSD
- 10 Gbit/s порт
- Unlimited Traffic
- **$224/міс**
- **Може бути вимкнений** коли навантаження низьке (економія)

**Сервіси (активується при піковому навантаженні):**
- w100n_core (Go) + плагіни (мікросервіси) - синхронізовано з DO
- Відео меню мікросервіс (обробка відео)
- Next.js фронтенди (builder, адмін, вебсайти) - синхронізовано з DO
- Redis для кешування
- PM2 для процесів
- Docker для контейнерів
- Nginx для reverse proxy
- Домени через Cloudflare DNS → load balancing з DO

**Contabo Server 2 (опціонально): Extreme Scaling**

**Характеристики:**
- 32 cores, 128GB RAM, 2x 1TB NVMe
- 10 Gbit/s порт
- **$224/міс**
- **Активується тільки при дуже високому навантаженні**

**Сервіси:**
- Додаткові мікросервіси для дуже високого навантаження
- Додаткове навантаження

**DO Spaces (Storage):**
- Backups та медіа файли
- **$5/міс** (250GB)

### 3. DigitalOcean Managed Databases

**DO Managed PostgreSQL:**
- 2 vCPU / 4GB RAM
- Автоматичні бекапи
- High availability (автоматичний failover)
- **$60/міс**

**DO Managed MongoDB:**
- 2 vCPU / 4GB RAM
- ReplicaSet з автоматичним failover
- Автоматичні бекапи
- **$60/міс**

**DO Spaces (Storage):**
- Backups та медіа файли
- **$5/міс** (250GB)

### 4. Cloudflare (DNS + CDN)

**Cloudflare DNS:**
- Стабільний DNS з глобальною мережею
- Динамічне перенаправлення трафіку
- Health checks для автоматичного failover
- Load balancing між Contabo та DO
- DDoS захист
- Безкоштовно (Pro $20/міс для додаткових функцій)

**Cloudflare CDN:**
- Кешування статики
- DDoS захист
- Безкоштовно (до 100GB/міс)

### 5. CDN для відео/фото (Мікросервіс відео меню)

**Варіанти CDN:**

**Варіант 1: Cloudflare Stream + R2**
- Cloudflare Stream для відео: ~$1/1000 хвилин перегляду
- Cloudflare R2 для storage: $0.015/GB + $0.36/GB egress
- Глобальна мережа edge серверів
- DDoS захист
- Автоматичне кешування

**Варіант 2: BunnyCDN (рекомендовано для економії)**
- Storage: $0.01/GB
- Bandwidth: $0.01-0.05/GB (залежить від регіону)
- Video Library: $0.01/GB storage + $0.01/GB bandwidth
- Pull Zone для фото: $0.01/GB bandwidth
- Дешевше ніж Cloudflare для великих обсягів

**Варіант 3: DigitalOcean Spaces + CDN**
- Spaces: $5/міс (250GB) + $0.02/GB storage
- CDN bandwidth: $0.12/GB
- Простіше інтеграція з DO інфраструктурою

**Рекомендація:**
- **BunnyCDN** для економії при великих обсягах відео/фото
- Або **Cloudflare Stream + R2** для інтеграції з Cloudflare DNS

**Інтеграція:**
- Мікросервіс відео меню завантажує відео/фото на CDN
- Автоматичне кешування на edge серверах
- Швидка доставка по всьому світу
- Автоматичне масштабування при збільшенні трафіку


## Реплікація баз даних

### PostgreSQL (DO Managed Database)

**Managed PostgreSQL:**
- Автоматичні backups (щодня)
- High availability (автоматичний failover)
- Read replicas (опціонально)
- Connection pooling (вбудований)
- **Переваги:**
  - Не навантажує Contabo сервери
  - Легше масштабувати
  - Автоматичне управління
  - Високий uptime

**Connection:**
- DO Droplets (Primary) підключаються до DO Managed PostgreSQL
- Contabo сервери (scaling) також підключаються до Managed DB
- Connection Manager керує підключеннями
- Connection string статичний для всіх серверів

**Failover:**
- DO Managed PostgreSQL має автоматичний failover (вбудований)
- Connection string залишається статичним (не потрібно оновлювати)
- Go Control Panel моніторить стан для алертів
- При проблемах - Managed DB автоматично переключається на standby
- Application продовжує використовувати той самий connection string (на DO та Contabo)

### MongoDB (DO Managed Database)

**Managed MongoDB:**
- ReplicaSet з автоматичним failover
- Автоматичні backups
- Oplog для синхронізації
- **Переваги:**
  - Не навантажує Contabo сервери
  - Легше масштабувати
  - Автоматичне управління
  - Високий uptime

**Connection:**
- DO Droplets (Primary) підключаються до DO Managed MongoDB
- Contabo сервери (scaling) також підключаються до Managed DB
- Connection Manager керує підключеннями
- Connection string статичний для всіх серверів

**Failover:**
- Автоматичний через Managed ReplicaSet (вбудований)
- Connection string залишається статичним (не потрібно оновлювати)
- Go Control Panel моніторить стан для алертів
- При проблемах - Managed DB автоматично переключається на standby
- Application продовжує використовувати той самий connection string (на DO та Contabo)

## Конфігурація w100n_core

### Database Connection Pool

```go
// internal/database/pool.go
type DBPool struct {
    PostgreSQL *sql.DB  // Connection до Managed PostgreSQL
    MongoDB    *mongo.Client  // Connection до Managed MongoDB
    healthCheck *HealthChecker
    logger     *Logger
    postgresConnection *sql.DB  // Статичний connection string до Managed DB
}

// Автоматичне переключення при недоступності
func (p *DBPool) GetPostgreSQL() *sql.DB {
    // Для Managed Databases connection string статичний
    // Failover обробляється автоматично на рівні Managed DB
    // Connection Manager потрібен тільки для переключення між Contabo та DO
    // при failover application серверів (не баз даних)
    
    // Перевірка здоров'я Managed DB
    if !p.healthCheck.IsManagedDBHealthy() {
        // Логування помилки, але connection string залишається той самий
        // Managed DB сам обробляє failover
        p.logger.Warn("Managed DB unhealthy, but connection string unchanged")
    }
    return p.postgresConnection  // Статичний connection string до Managed DB
}
```

### Environment Variables

**Важливо:** `.env` файли використовуються **ТІЛЬКИ для non-sensitive конфігурацій**. Всі секрети (паролі, API ключі, токени) зберігаються в **HashiCorp Vault** та отримуються через Vault API при старті додатку.

```env
# Non-sensitive configuration (може бути в .env)

# Databases (DigitalOcean Managed) - connection info (без паролів!)
POSTGRES_HOST=managed-postgres-do.internal
POSTGRES_PORT=25060  # Managed DB порт (не стандартний 5432)
POSTGRES_DB=w100n_db
# POSTGRES_USER та POSTGRES_PASSWORD - з Vault!
POSTGRES_SSLMODE=require  # Обов'язково для Managed DB

MONGO_HOST=managed-mongo-do.internal
MONGO_PORT=27017
MONGO_DB=w100n_db
MONGO_REPLICA_SET=w100n-rs
MONGO_TLS=true  # Обов'язково для Managed DB
# MONGO_USER та MONGO_PASSWORD - з Vault!

# Vault configuration
VAULT_ADDR=http://vault.internal:8200
VAULT_ROLE_ID=<approle-role-id>  # Для AppRole auth
VAULT_SECRET_ID=<approle-secret-id>  # Для AppRole auth (може бути через env або файл)
VAULT_SECRET_ID_FILE=/run/secrets/vault-secret-id  # Альтернатива (Docker secrets)

# Application Servers
APP_PRIMARY_HOST=do-droplet1.internal
APP_SCALING_HOST=contabo-server1.internal

# CDN (тільки URL, не API ключі!)
CDN_URL=https://cdn.example.com
CDN_PROVIDER=bunnycdn  # або cloudflare
# CDN_API_KEY - з Vault!

# Logging та monitoring (non-sensitive)
LOG_LEVEL=info
METRICS_PORT=9090
```

**Секрети, які зберігаються в Vault (НЕ в .env):**
- `POSTGRES_USER` та `POSTGRES_PASSWORD`
- `MONGO_USER` та `MONGO_PASSWORD`
- `DO_API_TOKEN` (DigitalOcean API)
- `CLOUDFLARE_API_TOKEN`
- `CDN_API_KEY` (BunnyCDN/Cloudflare)
- `JWT_SECRET`
- `ENCRYPTION_KEY`
- SSL/TLS private keys
- OAuth client secrets
- Інші sensitive дані

## Go Control Panel - Failover Logic

### Health Check

```go
// internal/monitoring/health.go
type HealthChecker struct {
    servers []Server
    managedDBHealth *DBHealth  // Для Managed Databases (статичний connection string)
    doHealth *ServerHealth     // DO Primary сервери
    contaboHealth *ServerHealth // Contabo Scaling сервер
}

func (h *HealthChecker) Check() {
    // Перевірка DO серверів (Primary)
    // Перевірка DO Managed PostgreSQL (через managedDBHealth)
    // Перевірка DO Managed MongoDB (через managedDBHealth)
    // Якщо DO навантаження високе → trigger scaling на Contabo
    // Якщо DO недоступний → trigger failover на Contabo
    // Managed DB сам обробляє свій failover (connection string не змінюється)
    // Оновлення Cloudflare DNS для load balancing або перенаправлення трафіку
}
```

### Scaling Process (DO → Contabo при піковому навантаженні)

1. **Виявлення високого навантаження** (CPU > 80% або RAM > 90% на DO серверах протягом 5 хвилин)
2. **Перевірка Contabo серверів** (чи доступні для scaling)
3. **Перевірка DO Managed Databases** (чи доступні)
4. **Активація Contabo для scaling** (синхронізація конфігурацій з DO)
5. **Connection strings залишаються незмінними** (Managed DB connection string статичний)
6. **Оновлення Cloudflare DNS** (load balancing між DO та Contabo)
7. **Перезапуск сервісів на Contabo** (w100n_core + фронтенди, синхронізовано з DO)
8. **Алерт** (Email/Slack про активацію scaling)
9. **Моніторинг навантаження** (коли навантаження знижується - можна вимкнути Contabo)
10. **CDN продовжує працювати** (відео/фото доступні незалежно)

### Failover Process (DO → Contabo при збоях)

1. **Виявлення проблеми** (3 failed checks підряд на DO серверах)
2. **Перевірка Contabo серверів** (чи доступні)
3. **Перевірка DO Managed Databases** (чи доступні)
4. **Активація Contabo для failover** (синхронізація конфігурацій з DO)
5. **Connection strings залишаються незмінними** (Managed DB connection string статичний)
6. **Оновлення Cloudflare DNS** (перенаправлення трафіку на Contabo)
7. **Перезапуск сервісів на Contabo** (w100n_core + фронтенди)
8. **Алерт** (Email/Slack про failover)
9. **Моніторинг відновлення DO** (коли DO відновлюється - можна повернутись)
10. **CDN продовжує працювати** (відео/фото доступні незалежно)

### Scaling Down Process (Contabo → DO коли навантаження знижується)

1. **Виявлення низького навантаження** (CPU < 40% та RAM < 50% на DO серверах протягом 10 хвилин)
2. **Перевірка що Contabo активний** (для scaling, не failover)
3. **Оновлення Cloudflare DNS** (повернення трафіку на DO)
4. **Вимкнення Contabo серверів** (економія)
5. **Алерт** (Email/Slack про вимкнення scaling)
6. **Моніторинг навантаження** (готовність до повторної активації при потребі)

## Deployment Strategy

### Initial Setup

1. **DigitalOcean (Primary + Databases):**

                        - Створити Managed PostgreSQL (2 vCPU / 4GB RAM)
                        - Створити Managed MongoDB (2 vCPU / 4GB RAM)
                        - Створити 3-4 Droplets (Application Primary, Frontend Primary, Control Panel, опціонально Additional)
                        - Встановити w100n_core + плагіни (мікросервіси) на DO Droplet 1
                        - Встановити відео меню мікросервіс на DO Droplet 1
                        - Встановити Next.js фронтенди на DO Droplet 2
                        - Встановити Redis для кешування на DO Droplet 1
                        - Встановити Nginx для reverse proxy на DO Droplets
                        - Встановити Go Control Panel + Monitoring на DO Droplet 3
                        - Налаштувати підключення до Managed Databases
                        - Налаштувати VPC для внутрішньої комунікації

2. **Contabo Dedicated (Scaling - опціонально, можна додати пізніше):**

                        - Замовити Contabo сервер (32 cores, 128GB RAM, 2x1TB NVMe)
                        - Встановити w100n_core + плагіни (мікросервіси) - синхронізовано з DO
                        - Встановити відео меню мікросервіс - синхронізовано з DO
                        - Встановити Next.js фронтенди - синхронізовано з DO
                        - Встановити Redis для кешування
                        - Встановити Nginx для reverse proxy
                        - Налаштувати підключення до DO Managed Databases (той самий connection string)
                        - Налаштувати VPN tunnel між Contabo та DO
                        - Сервер може бути вимкнений до моменту пікового навантаження (економія)

3. **Cloudflare (DNS):**

                        - Налаштувати DNS записи
                        - Налаштувати health checks
                        - Налаштувати автоматичне перенаправлення трафіку
                        - Налаштувати load balancing між Contabo та DO

4. **CDN (BunnyCDN або Cloudflare):**

                        - Створити CDN аккаунт
                        - Налаштувати Pull Zone для фото
                        - Налаштувати Video Library для відео
                        - Інтегрувати з мікросервісом відео меню

5. **Go Control Panel:**

                        - Налаштувати health checks для всіх серверів (DO Primary)
                        - Налаштувати scaling logic (DO → Contabo при піковому навантаженні)
                        - Налаштувати failover logic (DO → Contabo при збоях)
                        - Налаштувати Cloudflare DNS API інтеграцію (load balancing)
                        - Налаштувати алерти (Email/Slack)
                        - Налаштувати моніторинг баз даних
                        - Налаштувати автоматичну активацію/вимкнення Contabo при зміні навантаження

### Maintenance

- **Бекапи:** Автоматичні щодня на DO Managed Databases, синхронізація на DO Spaces
- **Оновлення:** Rolling updates (спочатку на DO Primary, потім синхронізація на Contabo якщо активний)
- **Моніторинг:** Grafana + Prometheus + Loki (на DO Droplet 3)
- **DNS:** Всі домени через Cloudflare DNS з динамічним load balancing
- **Синхронізація:** Автоматична кожні 30 сек (конфігурації, код, медіа на CDN, DO → Contabo)
- **Масштабування:** При збільшенні навантаження → автоматична активація Contabo або додавання DO Droplets
- **CDN:** Автоматичне кешування та масштабування для медіа контенту

### Масштабування

**Горизонтальне масштабування:**
- Додавання більше DO Droplets при збільшенні навантаження
- Активація Contabo серверів при піковому навантаженні
- Додавання другого Contabo сервера при дуже високому навантаженні
- Масштабування DO Managed Databases (збільшення RAM/CPU)
- Автоматичне оновлення Cloudflare DNS для load balancing
- Синхронізація конфігурацій на нові сервери (DO → Contabo)

**Вертикальне масштабування:**
- Збільшення RAM/CPU на DO Droplets (через DO API)
- Збільшення RAM/CPU на DO Managed Databases (через DO API)
- Масштабування Contabo сервера (upgrade до більшого плану, якщо потрібно)
- Автоматичний перезапуск сервісів після зміни розміру

**Приклад масштабування:**
```yaml
# configs/autoscaling.yaml
rules:
  - name: "do_primary_servers"
    min_servers: 2
    max_servers: 4
    scale_up_threshold: 80% CPU або 90% RAM
    scale_down_threshold: 50% CPU та 60% RAM
    server_type: "4vCPU-8GB"
    # Додавання більше DO Droplets
    
  - name: "contabo_scaling"
    min_servers: 0  # Може бути вимкнений
    max_servers: 2
    scale_up_threshold: 85% CPU або 95% RAM на DO (пікове навантаження)
    scale_down_threshold: 40% CPU та 50% RAM на DO (навантаження нормалізувалось)
    server_type: "32cores-128gb"
    # Активація Contabo при піковому навантаженні
    
  - name: "do_databases"
    scale_up_threshold: 80% CPU або 90% RAM
    scale_down_threshold: 50% CPU та 60% RAM
    # Масштабування через DO API
    
  - name: "cdn_bandwidth"
    # Автоматичне масштабування через CDN провайдера
    # BunnyCDN/Cloudflare автоматично масштабуються
```

## Безпека та мережа

### VPC та Private Network

**DigitalOcean VPC:**
- Створити VPC для всіх Droplets
- Private IP адреси для внутрішньої комунікації
- Ізоляція від публічного інтернету для БД
- Firewall rules на рівні VPC

**VPN Tunnel:**
- VPN між Contabo та DigitalOcean серверами
- WireGuard або OpenVPN
- Шифрування трафіку між локаціями
- Автоматичне перепідключення при збоях
- Private network для Managed Databases

**Network Security:**
```yaml
# Firewall rules
- Allow: SSH (port 22) тільки з white-listed IP
- Allow: HTTPS (port 443) з усіх
- Allow: HTTP (port 80) → redirect to HTTPS
- Deny: Всі інші порти
- Allow: Internal VPC communication
- Allow: Database ports тільки в VPC
```

### Secrets Management

**HashiCorp Vault (обраний метод):**

DigitalOcean не надає власного сервісу для зберігання секретів (як AWS Secrets Manager), тому використовуємо **HashiCorp Vault** для безпечного зберігання та управління секретами.

**Чому HashiCorp Vault:**
- ✅ Безпечне зберігання паролів БД, API ключів, SSL сертифікатів
- ✅ Ротація паролів (автоматична кожні 90 днів)
- ✅ Шифрування sensitive даних (AES-256)
- ✅ Audit log всіх доступів до secrets (важливо для HIPAA)
- ✅ Role-based access control (RBAC)
- ✅ Self-hosted рішення (повний контроль)
- ✅ Інтеграція з Go додатками через Vault API
- ✅ Підтримка dynamic secrets (автоматична генерація)
- ✅ Policies для fine-grained access control

**Розміщення:**
- Vault розгортається на **DO Droplet 3** (разом з Go Control Panel + Monitoring)
- Використовує тільки VPC network (не доступний з публічного інтернету)
- Backup через Vault's integrated storage backend (можна на DO Spaces)

**Що зберігається в Vault:**
1. **Database credentials:**
   - PostgreSQL connection strings (Managed DB)
   - MongoDB connection strings (Managed DB)
   - Database passwords (автоматична ротація)
   
2. **API Keys:**
   - DigitalOcean API tokens
   - Cloudflare API tokens
   - CDN API keys (BunnyCDN/Cloudflare)
   
3. **Application secrets:**
   - JWT signing keys
   - Encryption keys
   - OAuth client secrets
   
4. **Infrastructure secrets:**
   - SSL/TLS certificates (private keys)
   - VPN keys
   - SSH keys (опціонально)

**Architecture:**
```
DO Droplet 3 (Control Panel):
├── Go Control Panel
├── Monitoring (Loki, Prometheus, Grafana)
└── HashiCorp Vault (Docker container)
    ├── Storage backend (file-based або Consul)
    ├── Audit logs → Loki
    └── Metrics → Prometheus
```

**Security:**
- Vault доступний тільки в VPC (private IP)
- TLS для всіх з'єднань (mTLS опціонально)
- Token-based authentication для додатків
- AppRole authentication для автоматизованих систем
- Unseal keys зберігаються окремо (DO Spaces або external storage)

**Backup Strategy:**
- Vault storage backend backup щодня
- Backup зберігається на DO Spaces (encrypted)
- Unseal keys в secure external storage (HIPAA requirement)
- Retention: 30 днів (можна збільшити для audit)

**Implementation:**
```go
// internal/secrets/vault.go
package secrets

import (
    "context"
    "fmt"
    "sync"
    "time"

    "github.com/hashicorp/vault/api"
)

type VaultSecretsManager struct {
    client *api.Client
    cache  map[string]*SecretCache
    mutex  sync.RWMutex
    ctx    context.Context
}

type SecretCache struct {
    value     string
    expiresAt time.Time
}

// NewVaultSecretsManager creates new Vault client
func NewVaultSecretsManager(vaultAddr, vaultToken string) (*VaultSecretsManager, error) {
    config := api.DefaultConfig()
    config.Address = vaultAddr // e.g., "http://vault.internal:8200"
    
    client, err := api.NewClient(config)
    if err != nil {
        return nil, err
    }
    
    client.SetToken(vaultToken)
    
    return &VaultSecretsManager{
        client: client,
        cache:  make(map[string]*SecretCache),
        ctx:    context.Background(),
    }, nil
}

// GetSecret retrieves secret from Vault (with caching)
func (v *VaultSecretsManager) GetSecret(path, key string) (string, error) {
    // Check cache first
    v.mutex.RLock()
    if cached, ok := v.cache[path+"/"+key]; ok {
        if time.Now().Before(cached.expiresAt) {
            v.mutex.RUnlock()
            return cached.value, nil
        }
    }
    v.mutex.RUnlock()
    
    // Fetch from Vault
    secret, err := v.client.Logical().Read(path)
    if err != nil {
        return "", err
    }
    
    if secret == nil || secret.Data == nil {
        return "", fmt.Errorf("secret not found at path: %s", path)
    }
    
    value, ok := secret.Data[key].(string)
    if !ok {
        return "", fmt.Errorf("key %s not found in secret at path: %s", key, path)
    }
    
    // Cache for 5 minutes
    v.mutex.Lock()
    v.cache[path+"/"+key] = &SecretCache{
        value:     value,
        expiresAt: time.Now().Add(5 * time.Minute),
    }
    v.mutex.Unlock()
    
    return value, nil
}

// GetDatabaseCredentials gets DB credentials from Vault
func (v *VaultSecretsManager) GetDatabaseCredentials(dbType string) (username, password string, err error) {
    path := fmt.Sprintf("secret/data/databases/%s", dbType)
    
    username, err = v.GetSecret(path, "username")
    if err != nil {
        return "", "", err
    }
    
    password, err = v.GetSecret(path, "password")
    if err != nil {
        return "", "", err
    }
    
    return username, password, nil
}

// GetAPIKey retrieves API key from Vault
func (v *VaultSecretsManager) GetAPIKey(service string) (string, error) {
    path := fmt.Sprintf("secret/data/api-keys/%s", service)
    return v.GetSecret(path, "key")
}
```

**Vault Configuration Example:**
```hcl
# vault.hcl
storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 0
  tls_cert_file = "/vault/certs/vault.crt"
  tls_key_file  = "/vault/certs/vault.key"
}

api_addr = "https://vault.internal:8200"
cluster_addr = "https://vault.internal:8201"

ui = true
log_level = "INFO"

# Audit logging
audit {
  enabled = true
  file {
    file_path = "/vault/logs/audit.log"
    format    = "json"
  }
}
```

**Docker Compose для Vault:**
```yaml
# docker-compose.vault.yml
version: '3.8'
services:
  vault:
    image: hashicorp/vault:latest
    container_name: vault
    restart: unless-stopped
    volumes:
      - ./vault/data:/vault/data
      - ./vault/config:/vault/config
      - ./vault/logs:/vault/logs
      - ./vault/certs:/vault/certs
    ports:
      - "8200:8200"
    cap_add:
      - IPC_LOCK
    environment:
      - VAULT_ADDR=http://0.0.0.0:8200
      - VAULT_API_ADDR=http://0.0.0.0:8200
    command: server -config=/vault/config/vault.hcl
    networks:
      - vpc_network
    healthcheck:
      test: ["CMD", "vault", "status"]
      interval: 30s
      timeout: 5s
      retries: 3
```

**Initialization та Unsealing:**
```bash
# Initialize Vault (виконується один раз)
vault operator init -key-shares=5 -key-threshold=3

# Зберегти unseal keys в secure storage
# Unseal Vault (після кожного перезапуску)
vault operator unseal <unseal-key-1>
vault operator unseal <unseal-key-2>
vault operator unseal <unseal-key-3>

# Налаштування policies та secrets
vault policy write w100n-app-policy - <<EOF
path "secret/data/databases/*" {
  capabilities = ["read"]
}

path "secret/data/api-keys/*" {
  capabilities = ["read"]
}
EOF

# Створити AppRole для автоматизованого доступу
vault auth enable approle
vault write auth/approle/role/w100n-core \
    token_policies="w100n-app-policy" \
    token_ttl=1h \
    token_max_ttl=4h
```

**Integration з w100n_core:**
```go
// При старті додатку
vaultManager, err := secrets.NewVaultSecretsManager(
    os.Getenv("VAULT_ADDR"),
    os.Getenv("VAULT_ROLE_ID"),     // AppRole role_id
    os.Getenv("VAULT_SECRET_ID"),   // AppRole secret_id
)

// Використання в коді замість os.Getenv()
dbPassword, err := vaultManager.GetSecret("secret/data/databases/postgres", "password")
```

**Примітка:** `.env` файли НЕ використовуються для секретів. Тільки для не-sensitive конфігурацій (наприклад, `LOG_LEVEL=info`). Всі секрети отримуються з Vault.

### Firewall та Rate Limiting

**UFW на всіх серверах:**
- Мінімальні відкриті порти
- Fail2ban для захисту від brute-force
- Rate limiting на Nginx (10-20 req/sec per IP для API, 100 req/sec для статики)
- DDoS захист через Cloudflare

**Nginx Rate Limiting:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req zone=api burst=20 nodelay;
```

## Backup та Disaster Recovery

### Backup Strategy

**PostgreSQL (DO Managed):**
- Автоматичні backups (вбудовані, щодня)
- Point-in-time recovery (PITR) - вбудований
- Retention налаштовується в DO панелі:
  - **6 років для PHI даних** (HIPAA вимога)
  - 30 днів для non-PHI даних (за замовчуванням)
- Додаткові backups на DO Spaces для географічного розподілення
- External storage для PHI даних (обов'язково)
- Тестування відновлення: щомісяця

**MongoDB (DO Managed):**
- Автоматичні backups (вбудовані, щодня)
- Oplog backup (continuous, вбудований)
- Retention налаштовується в DO панелі:
  - **6 років для PHI даних** (HIPAA вимога)
  - 30 днів для non-PHI даних (за замовчуванням)
- Додаткові backups на DO Spaces для географічного розподілення
- External storage для PHI даних (обов'язково)

**Application Files:**
- Щоденні backups коду та конфігурацій
- Retention: 7 днів
- Git репозиторій як додатковий backup

**Backup Locations (HIPAA вимога - географічне розподілення):**
1. DO Managed Databases (вбудовані backups, регіон 1)
2. DigitalOcean Spaces (secondary, регіон 2)
3. External storage в іншому регіоні (обов'язково для PHI даних)
4. Всі backups шифруються (AES-256)
5. Автоматична синхронізація між локаціями

### RTO/RPO (Recovery Time/Point Objectives)

**RTO (Recovery Time Objective):**
- **< 15 хвилин** - час відновлення після збою
- Автоматичний failover: < 2 хвилини
- Manual intervention: < 13 хвилин

**RPO (Recovery Point Objective):**
- **< 5 хвилин** - максимальна втрата даних
- DO Managed Databases мають автоматичну реплікацію
- Point-in-time recovery (PITR) для PostgreSQL
- Oplog для MongoDB забезпечує zero data loss
- Continuous replication

### Disaster Recovery Plan

**Сценарії:**
1. **DO сервер недоступний** → Failover на Contabo (автоматично)
2. **DO регіон недоступний** → Manual failover на DO в іншому регіоні або Contabo
3. **DO Managed Databases недоступні** → Відновлення з backup (RTO: 1 година)
4. **Обидва недоступні** → Відновлення з backup (RTO: 1 година)

**Failback (повернення на DO Primary):**
- Коли DO відновлюється, можна повернутись на Primary
- Поступове переключення (спочатку синхронізація, потім переключення)
- Оновлення Cloudflare DNS для повернення трафіку на DO
- Мінімальний downtime при failback

**Scaling Down (вимкнення Contabo після нормалізації навантаження):**
- Коли навантаження знижується, Contabo автоматично вимикається (економія)
- Поступове перенаправлення трафіку на DO
- Оновлення Cloudflare DNS для повернення трафіку на DO
- Мінімальний downtime при scaling down

**Testing:**
- Щомісяця: тестування відновлення з backup
- Щокварталу: повне disaster recovery тестування
- Документація всіх процедур

## Моніторинг та Observability

### Centralized Logging

**Loki + Grafana:**
- Збір логів з усіх серверів (w100n_core, фронтенди, БД)
- Structured logging (JSON формат)
- Retention: 30 днів (6 років для audit logs з PHI)
- Log aggregation та аналіз
- Alerting на критичні помилки
- Розміщення: на DO Droplet 3 (разом з Control Panel)

**Log Levels:**
- ERROR: критичні помилки (алерт негайно)
- WARN: попередження (алерт через 5 хвилин)
- INFO: інформаційні повідомлення
- DEBUG: тільки для розробки

### Distributed Tracing

**Jaeger для tracing:**
- Відстеження запитів через всі мікросервіси
- Performance monitoring
- Виявлення bottlenecks
- Trace correlation з логами
- Розміщення: на DO Droplet 3 (разом з Control Panel) або окремий сервіс

**Implementation:**
```go
// OpenTelemetry integration
tracer := otel.Tracer("w100n_core")
ctx, span := tracer.Start(ctx, "database.query")
defer span.End()
```

### Metrics та Alerting

**Prometheus + Grafana:**
- CPU, RAM, Disk, Network метрики
- Application metrics (request rate, latency, errors)
- Database metrics (connections, queries, replication lag)
- Business metrics (user activity, transactions)
- Розміщення: на DO Droplet 3 (разом з Control Panel)

**Alerting Rules:**
```yaml
alerts:
  - name: HighCPU
    condition: cpu_usage > 80% for 5m
    severity: warning
    
  - name: HighMemory
    condition: memory_usage > 90% for 5m
    severity: critical
    
  - name: DiskSpace
    condition: disk_usage > 85%
    severity: warning
    
  - name: DatabaseReplicationLag
    condition: replication_lag > 10s
    severity: critical
    
  - name: FailedHealthChecks
    condition: failed_checks > 3
    severity: critical
    
  - name: HighErrorRate
    condition: error_rate > 5% for 5m
    severity: warning
```

**Notification Channels:**
- Email (критичні алерти)
- Slack (всі алерти)
- PagerDuty (критичні алерти, 24/7)

### SLA/SLO Metrics

**Service Level Objectives:**
- **Infrastructure SLA (DigitalOcean):** 99.99% (52.56 хвилин downtime/рік)
- **Application SLA (з урахуванням failover):** 99.9% (8.76 годин downtime/рік)
- **Response Time:** P95 < 500ms, P99 < 1s
- **Error Rate:** < 0.1%
- **Target Uptime:** 99.99%+ (з автоматичним failover)

## CI/CD Pipeline

### Deployment Pipeline

**GitHub Actions / GitLab CI:**

```yaml
stages:
  1. Code push → Trigger pipeline
  2. Tests:
     - Unit tests
     - Integration tests
     - Security scanning
  3. Build:
     - Docker images
     - Tag з версією
  4. Deploy to Staging (DO Droplet 1):
     - Deploy Docker images
     - Run database migrations
     - Smoke tests
  5. Deploy to Production (Contabo):
     - Blue-green deployment
     - Health checks
     - Rollback при проблемах
     - Синхронізація на DO standby
```

**Deployment Strategy:**
- **Blue-Green:** Zero downtime deployments
- **Canary:** Поступове розгортання (10% → 50% → 100%)
- **Rolling:** Поступове оновлення з health checks

### Rollback Strategy

**Автоматичний Rollback:**
- При failed health checks після deployment
- При error rate > 5% протягом 5 хвилин
- При критичних помилок в логах

**Manual Rollback:**
- Збереження попередніх версій Docker images
- Database migrations з можливістю rollback
- Git tags для версіонування

**Rollback Process:**
1. Виявлення проблеми (health checks / metrics)
2. Автоматичний rollback до попередньої версії
3. Перевірка health
4. Алерт команді
5. Аналіз проблеми

## Database Optimization

### Connection Pooling

**PostgreSQL (DO Managed):**
- Connection pooling вбудований в Managed Database
- Не потрібен окремий PgBouncer
- Налаштування через connection string параметри
- Max connections налаштовується в DO панелі
- Автоматичне управління пулом з'єднань

**MongoDB (DO Managed):**
- Connection pool size: 50-100 (налаштовується в connection string)
- Max idle time: 30 хвилин
- Connection timeout: 10 секунд
- Автоматичне управління пулом з'єднань

**Configuration:**
```yaml
# Connection strings для Managed Databases
POSTGRES_HOST=managed-postgres-do.internal
POSTGRES_PORT=25060  # Managed DB порт
POSTGRES_DB=w100n_db
# Connection pooling налаштовується автоматично

MONGO_HOST=managed-mongo-do.internal
MONGO_PORT=27017
MONGO_DB=w100n_db
# Connection pool size в connection string
```

### Database Monitoring

**Slow Query Log:**
- Запити > 1 секунда → log
- Аналіз та оптимізація
- Індексація на основі аналізу

**Connection Pool Monitoring:**
- Активні з'єднання
- Waiting connections
- Connection errors

**Replication Lag Monitoring:**
- PostgreSQL (Managed): Моніторинг через DO API та метрики
- MongoDB (Managed): Моніторинг через DO API та метрики
- Alert при lag > 10 секунд
- Моніторинг через Prometheus exporters

### Database Migrations

**Migration Strategy:**
- Версіонування міграцій
- Backward compatible міграції
- Тестування на staging перед production
- Rollback план для кожної міграції

**Tools:**
- PostgreSQL: `golang-migrate` або `Flyway`
- MongoDB: Custom migration scripts

## Network Performance

### Latency Optimization

**Мережеві маршрути:**
- Перевірка latency між Contabo та DO
- Оптимізація мережевих маршрутів
- Використання найближчих регіонів
- VPN tunnel для безпечного зв'язку

**CDN для статики:**
- Cloudflare CDN для статичних файлів
- Кешування на edge locations
- Автоматичне invalidation при оновленнях

### Caching Strategy

**Redis для кешування:**
- Application-level caching
- Session storage
- Query result caching
- Cache invalidation strategy
- Розміщення: на DO Droplet 1 (Primary) та Contabo (якщо активний для scaling)

**CDN Caching:**
- Static assets (images, CSS, JS)
- Cache-Control headers
- ETag для validation

**Cache Layers:**
1. Browser cache
2. CDN cache (Cloudflare)
3. Application cache (Redis)
4. Database query cache

## Cost Optimization

### Cost Monitoring

**Tracking:**
- Витрати по компонентах (Droplets, Load Balancer, Storage)
- Використання ресурсів (CPU, RAM, Disk, Network)
- Cost alerts при перевищенні бюджету

**Cost Alerts:**
- Щомісячний бюджет: $500-800 (залежить від конфігурації)
- Alert при 80% бюджету
- Alert при 100% бюджету

### Resource Optimization

**Оптимізація витрат:**
- Використання DO Primary для основного навантаження (стабільніше, SLA гарантовано)
- DO Managed Databases (не потрібно управляти самостійно)
- Contabo використовується тільки при піковому навантаженні (може бути вимкнений, економія)
- BunnyCDN для економії на медіа контенті
- Автоматичне вимкнення Contabo коли навантаження нормалізується

**Reserved Instances:**
- Розглянути reserved instances для DO Managed Databases
- Економія до 20% на довгострокових сервісах
- Contabo сервери вже мають фіксовану ціну

## HIPAA Compliance

### Вимоги HIPAA

**HIPAA (Health Insurance Portability and Accountability Act)** вимагає:
- Захист PHI (Protected Health Information)
- Шифрування даних (at rest та in transit)
- Access controls та audit logs
- Business Associate Agreements (BAA)
- Risk assessment та management

### Технічні вимоги

**Шифрування даних:**

**At Rest:**
- PostgreSQL (DO Managed): Encryption at rest (вбудований в Managed Database)
- MongoDB (DO Managed): Encryption at rest (WiredTiger encryption, вбудований)
- Contabo сервери: Disk-level encryption (LUKS/dm-crypt) для локальних даних
- Backup encryption: AES-256 (автоматично для Managed Databases)
- DigitalOcean Spaces: Server-side encryption
- Всі диски на серверах з шифруванням

**In Transit:**
- TLS 1.3 для всіх з'єднань
- HTTPS для всіх API endpoints
- VPN для зв'язку між серверами
- Database connections через SSL/TLS

**Access Controls:**
- Role-based access control (RBAC)
- Multi-factor authentication (MFA) для адміністраторів
- Principle of least privilege
- Regular access reviews (щокварталу)

**Audit Logging:**
- Логування всіх доступів до PHI
- Логування змін конфігурацій
- Логування доступу до баз даних
- Retention: 6 років (HIPAA вимога)
- Immutable logs (захист від змін)

**Implementation:**
```go
// Audit logging для PHI access
type AuditLog struct {
    Timestamp   time.Time
    UserID      string
    Action      string
    Resource    string
    IPAddress   string
    Result      string // success/failure
    PHIAccessed bool
}
```

### Business Associate Agreement (BAA)

**DigitalOcean BAA:**
- Підписати BAA з DigitalOcean
- Перевірити, що DO підтримує HIPAA compliance
- Документувати всі third-party сервіси

**Contabo сервери (для scaling):**
- Підписати BAA з Contabo (якщо використовується для PHI)
- Перевірити compliance провайдера
- Документувати всі third-party сервіси
- Врахувати що Contabo може бути вимкнений (не завжди активний)

### Risk Assessment

**Щорічна оцінка ризиків:**
- Ідентифікація загроз
- Оцінка вразливостей
- План зменшення ризиків
- Документація всіх процедур

**Security Controls:**
- Firewall rules
- Intrusion detection
- Regular security scans
- Penetration testing (щорічно)

### Data Backup та Recovery

**HIPAA вимоги:**
- Регулярні backups
- Тестування відновлення
- Географічне розподілення backups
- Шифрування backups

**Retention (HIPAA вимоги):**
- Audit logs: Мінімум 6 років (HIPAA вимога)
- PHI backups: Мінімум 6 років (HIPAA вимога)
- Non-PHI backups: 30 днів
- Secure deletion при закінченні retention (з документацією)

### Incident Response Plan

**Процедура при data breach:**
1. Виявлення інциденту
2. Ізоляція системи
3. Оцінка масштабу
4. Повідомлення (в межах 60 днів)
5. Документація інциденту
6. План запобігання

### Training та Documentation

**Обов'язкове:**
- Training персоналу по HIPAA
- Security awareness training
- Документація всіх процедур
- Regular updates при змінах

### Compliance Checklist

- [ ] Шифрування даних (at rest та in transit)
- [ ] Access controls та RBAC
- [ ] Audit logging (6 років retention)
- [ ] BAA з усіма провайдерами
- [ ] Risk assessment (щорічно)
- [ ] Incident response plan
- [ ] Training персоналу
- [ ] Regular security scans
- [ ] Penetration testing (щорічно)
- [ ] Documentation всіх процедур

## Файли для створення

1. `Ideas/Servers/ARCHITECTURE_HYBRID_INFRASTRUCTURE.md` - цей документ
2. `scripts_server/failover-handler.sh` - скрипт для failover (Contabo → DO)
3. `scripts_server/setup-vpn.sh` - налаштування VPN між Contabo та DO
4. `scripts_server/backup-sync.sh` - синхронізація backups з DO Spaces та External storage
5. `scripts_server/restore-test.sh` - тестування відновлення з backup
6. `scripts_server/setup-cloudflare-dns.sh` - налаштування Cloudflare DNS з health checks
7. `scripts_server/sync-media-to-cdn.sh` - синхронізація медіа файлів на CDN
8. `internal/monitoring/health.go` - health checks в Go
9. `internal/monitoring/failover.go` - failover logic в Go
10. `internal/monitoring/audit.go` - audit logging для HIPAA
11. `internal/secrets/vault.go` - HashiCorp Vault integration для secrets management
12. `docker-compose.vault.yml` - Docker Compose конфігурація для Vault
13. `vault/config/vault.hcl` - Vault server конфігурація
14. `vault/policies/w100n-app-policy.hcl` - Vault policy для w100n_core
15. `scripts_server/vault-init.sh` - скрипт для ініціалізації Vault
16. `scripts_server/vault-unseal.sh` - скрипт для unseal Vault
17. `docs/vault-setup.md` - інструкція по налаштуванню Vault
12. `internal/database/pool.go` - database connection management для Managed DB
13. `configs/databases.yaml` - конфігурація Managed Databases
14. `configs/firewall.yaml` - firewall rules
15. `configs/backup.yaml` - backup конфігурація
16. `configs/hipaa-compliance.yaml` - HIPAA compliance checklist
17. `.github/workflows/deploy.yml` - CI/CD pipeline
18. `docs/runbooks/` - операційні runbooks
19. `docs/disaster-recovery.md` - disaster recovery plan

## Критерії успіху

- ✅ Автоматичний failover за < 2 хвилини
- ✅ Zero data loss (PostgreSQL WAL, MongoDB Oplog)
- ✅ Моніторинг всіх компонентів
- ✅ Алерти при проблемах
- ✅ Документація процесів
- ✅ **99.99%+ uptime** (з урахуванням failover)
- ✅ **Автоматичне масштабування** (DO Primary → Contabo Scaling при піковому навантаженні)
- ✅ **Синхронізація конфігурацій** (DO → Contabo)
- ✅ **Оптимальна вартість** (~$343/міс мінімальна без Contabo, економія коли Contabo вимкнений)
- ✅ **Динамічне змінювання** без downtime

### To-dos

#### ЕТАП 1: Базове налаштування сервера через API (ПЕРШИЙ ПРІОРИТЕТ - ПОТОЧНИЙ ЕТАП)

**Це фундаментальний етап - перші налаштування нового сервера через WebSocket API:**

- [x] Створити структуру `modules/start_server_setting` в плагіні `w100n_servers_control`
- [x] Реалізувати Go модуль для налаштування сервера (замість bash скриптів)
- [x] Реалізувати всі кроки налаштування в Go:
  - [x] Системні оновлення (apt update/upgrade)
  - [x] Встановлення базових пакетів (nginx, docker, nodejs, npm, ufw, fail2ban, etc.)
  - [x] Встановлення Go 1.23.6 (стабільна версія)
  - [x] Встановлення Node.js LTS через NVM (стабільна версія)
  - [x] Встановлення PM2 та pnpm
  - [x] Hardening SSH (генерація порта)
  - [x] Налаштування Firewall (UFW)
  - [x] Налаштування Fail2ban
  - [x] Kernel security hardening (sysctl)
  - [x] Docker security configuration
  - [x] Nginx security headers та rate limiting
  - [x] Автоматичні security updates
  - [x] Malware scanning cron jobs
  - [x] Nginx cache permissions
  - [x] Timezone configuration
  - [x] Audit logging (auditd)
  - [x] Log rotation configuration (для всіх критичних логів)
  - [x] Time synchronization (Chrony з DNSSEC та DNSOverTLS)
  - [x] AppArmor configuration (Mandatory Access Control)
  - [x] File Integrity Monitoring (AIDE з щоденними перевірками)
  - [x] Resource limits configuration (захист від fork bombs)
  - [x] DNS Security (secure DNS з Cloudflare та Google, DNSSEC, DNSOverTLS)
  - [x] SSH hardening покращення (сучасні cipher, MAC, KexAlgorithms, прибрано застарілий Protocol 2)
  - [x] Fail2ban покращення (додано nginx-botsearch та nginx-limit-req jail)
  - [x] Kernel security покращення (ASLR, TCP keepalive, IP spoofing protection)
  - [x] Docker security покращення (userns-remap, socket permissions)
- [x] **Покращення безпеки (додано 6 нових функцій + оновлено 4 існуючі)**:
  - [x] **Log Rotation** (`configureLogRotation`): автоматична ротація логів для auth.log, nginx, fail2ban, security-scan, audit.log з правильними permissions
  - [x] **Time Synchronization** (`configureTimeSync`): встановлення Chrony з secure DNS (Cloudflare 1.1.1.1, Google 8.8.8.8), DNSSEC та DNSOverTLS
  - [x] **AppArmor** (`configureAppArmor`): Mandatory Access Control для ізоляції додатків, enforcing mode для всіх профілів
  - [x] **File Integrity Monitoring** (`setupFileIntegrityMonitoring`): AIDE з щоденними перевірками цілісності критичних файлів (cron job о 2:00)
  - [x] **Resource Limits** (`configureResourceLimits`): системні limits для захисту від fork bombs та DoS атак
  - [x] **DNS Security** (`configureDNSSecurity`): secure DNS з DNSSEC та DNSOverTLS через systemd-resolved
  - [x] **SSH Hardening покращення**: прибрано застарілий Protocol 2, додано сучасні KexAlgorithms (curve25519-sha256), Ciphers (chacha20-poly1305, AES-GCM), MACs (hmac-sha2-256-etm), зменшено LoginGraceTime до 30s, MaxSessions до 5, додано SSH logging
  - [x] **Fail2ban покращення**: додано backend=systemd, nginx-botsearch jail, nginx-limit-req jail для кращого захисту від ботів та rate limit violations
  - [x] **Kernel Security покращення**: додано ASLR (kernel.randomize_va_space=2), TCP keepalive параметри, IP spoofing protection (arp_ignore, arp_announce)
  - [x] **Docker Security покращення**: додано userns-remap для user namespace isolation, налаштування permissions для Docker socket
- [x] Створити GraphQL schema з Mutation `startServerSetup` та Subscription `serverSetupProgress`
- [x] Створити resolvers для WebSocket API (GraphQL Subscription)
- [x] Інтегрувати resolvers в core resolvers
- [x] **Критичні покращення безпеки та валідації (РЕАЛІЗОВАНО)**:
  - [x] SSH Host Key Verification (замість InsecureIgnoreHostKey) - `ssh_host_keys.go` з функціями saveHostKey, createHostKeyCallback, verifyHostKey
  - [x] Перевірка доступності сервера перед підключенням (CheckServerReachability) - інтегровано в `runPreSetupValidations()`
  - [x] Валідація username/password перед підключенням - `validateInputs()` в `validations.go`
  - [x] Перевірка версії ОС (Ubuntu 22.04 LTS або 24.04 LTS) - `detectOSVersion()` в `validations.go`
  - [x] Перевірка наявності sudo прав - `checkSudoRights()` в `validations.go`
  - [x] Перевірка вільності SSH порту перед зміною - `checkPortAvailability()` в `validations.go`
  - [x] Rollback механізм для критичних конфігурацій - `rollback.go` з автоматичним backup та rollback при помилках
  - [x] Безпечний перезапуск SSH після зміни порту (reload замість restart) - оновлено `hardenSSH()` в `security.go`
- [x] **Важливі перевірки перед налаштуванням (РЕАЛІЗОВАНО)**:
  - [x] Перевірка дискового простору (мінімум 10GB) - `checkDiskSpace()` в `validations.go`
  - [x] Перевірка інтернет-з'єднання - `checkInternetConnection()` в `validations.go`
  - [x] Перевірка наявності systemd - `checkSystemd()` в `validations.go`
  - [x] Перевірка версій встановлених пакетів після встановлення - `verifyInstalledPackage()` в `validations.go`
  - [x] Перевірка наявності критичних портів (80, 443) перед відкриттям в firewall - `checkPortsInUse()` в `validations.go`
  - [x] Перевірка наявності Go в PATH після встановлення - `verifyGoInstallation()` в `validations.go`, інтегровано в `setup.go`
  - [x] Перевірка наявності Node.js в PATH після встановлення - `verifyNodeJSInstallation()` в `validations.go`, інтегровано в `setup.go`
  - [x] Перевірка наявності Docker daemon після встановлення - `verifyDockerInstallation()` в `validations.go`, інтегровано в `setup.go`
  - [x] Перевірка наявності Nginx після встановлення - `verifyNginxInstallation()` в `validations.go`, інтегровано в `setup.go`
- [x] **Підтримка Ubuntu 22.04 LTS та 24.04 LTS (РЕАЛІЗОВАНО)**:
  - [x] Автоматичне визначення версії Ubuntu - `detectOSVersion()` читає `/etc/os-release` та перевіряє версію
  - [x] Сумісність пакетів для обох версій - всі пакети сумісні з Ubuntu 22.04 та 24.04
  - [x] Перевірка доступності пакетів для кожної версії - перевірка версії ОС перед встановленням
  - [x] Адаптація конфігурацій під версію ОС - SSH service name (`ssh` для Ubuntu 22/24), systemd команди
- [x] **Додаткові покращення (РЕАЛІЗОВАНО)**:
  - [x] Перевірка наявності ENCRYPTION_KEY перед шифруванням SSH ключів - `checkEncryptionKey()` в `validations.go`
  - [x] Перевірка наявності PostgreSQL підключення перед збереженням - `checkPostgresConnection()` в `validations.go`
  - [x] Перевірка наявності існуючого SSH ключа перед генерацією - перевірка в `loadServerConfig()` та `setupSSHKeys()`
  - [x] Перевірка наявності існуючих конфігурацій перед перезаписом - `checkExistingConfigs()` в `validations.go`
  - [x] Перевірка статусу AppArmor перед налаштуванням - `checkAppArmorStatus()` в `validations.go`
  - [x] Перевірка наявності SSL сертифікатів для Nginx - `checkSSLCertificates()` в `validations.go` (опціонально, не блокує налаштування)
  - [x] Перевірка наявності критичних логів після налаштування - `verifyCriticalLogs()` в `validations.go`
  - [x] Перевірка наявності cron jobs після налаштування - `verifyCronJobs()` в `validations.go`
  - [x] Перевірка статусу systemd services після налаштування - `verifySystemdServices()` в `validations.go`
  - [x] Фінальна комплексна перевірка всіх етапів - `runFinalComprehensiveCheck()` перевіряє SSH, Nginx, Docker, Go, Node.js, Firewall, Fail2ban, SSH порт
- [ ] Протестувати API через WebSocket з параметрами `username` та `password`
- [ ] Перевірити що всі кроки налаштування виконуються коректно
- [x] Додати обробку помилок та відновлення при збоях - rollback механізм автоматично відновлює конфігурації при помилках
- [x] Додати логування прогресу налаштування - `sendProgress()` використовується на всіх етапах
- [ ] Протестувати на реальному сервері Ubuntu 22.04 LTS
- [ ] Протестувати на реальному сервері Ubuntu 24.04 LTS

**Примітка:** 
- ✅ Підтримка Ubuntu 22.04 LTS та 24.04 LTS - реалізовано
- ✅ Всі критичні перевірки та покращення безпеки - реалізовано
- ✅ Валідації та перевірки інтегровані в процес налаштування
- ✅ Створено файли: `validations.go`, `ssh_host_keys.go`, `rollback.go` з усіма необхідними функціями
- ✅ Rollback механізм - реалізовано: автоматичний backup критичних конфігурацій перед змінами, автоматичний rollback при помилках
- ✅ Додаткові перевірки після налаштування (логи, cron, services) - реалізовано
- ✅ Фінальна комплексна перевірка всіх етапів - реалізовано: перевіряє SSH, Nginx, Docker, Go, Node.js, Firewall, Fail2ban, SSH порт
- ⚠️ Потрібно протестувати на реальних серверах Ubuntu 22.04 LTS та 24.04 LTS перед використанням в production

#### ЕТАП 2: Інфраструктура (наступні етапи)

- [ ] Створити DO Managed PostgreSQL (2 vCPU / 4GB RAM)
- [ ] Створити DO Managed MongoDB (2 vCPU / 4GB RAM)
- [ ] Створити 3-4 DO Droplets (Application Primary, Frontend Primary, Control Panel, опціонально Additional)
- [ ] Встановити w100n_core + плагіни на DO Droplet 1 (Primary)
- [ ] Встановити відео меню мікросервіс на DO Droplet 1
- [ ] Встановити Next.js фронтенди на DO Droplet 2 (Primary)
- [ ] Встановити Redis на DO Droplet 1
- [ ] Встановити Go Control Panel + Monitoring на DO Droplet 3
- [ ] Налаштувати VPC на DigitalOcean для внутрішньої комунікації
- [ ] Замовити Contabo сервер (32 cores, 128GB RAM, 2x1TB NVMe, 10 Gbit/s) - опціонально для scaling
- [ ] Встановити w100n_core + плагіни на Contabo Server 1 (синхронізовано з DO)
- [ ] Встановити відео меню мікросервіс на Contabo Server 1 (синхронізовано з DO)
- [ ] Встановити Next.js фронтенди на Contabo Server 1 (синхронізовано з DO)
- [ ] Встановити Redis на Contabo Server 1
- [ ] Налаштувати Cloudflare DNS з динамічним перенаправленням
- [ ] Налаштувати CDN (BunnyCDN або Cloudflare) для відео/фото
- [ ] Розробити Go сервіс Connection Manager для управління підключеннями та failover
- [ ] Інтегрувати Connection Manager з мікросервісами w100n_core
- [ ] Налаштувати підключення DO Droplets до DO Managed Databases
- [ ] Налаштувати підключення Contabo серверів до DO Managed Databases (той самий connection string)
- [ ] Налаштувати моніторинг та алерти для баз даних
- [ ] Протестувати автоматичне масштабування (DO → Contabo при піковому навантаженні)
- [ ] Протестувати автоматичний failover (DO → Contabo при збоях) та відновлення
- [ ] Протестувати scaling down (вимкнення Contabo коли навантаження знижується)
- [ ] Інтегрувати Cloudflare DNS API для автоматичного перенаправлення
- [ ] Інтегрувати CDN API для автоматичного завантаження медіа
- [ ] Реалізувати Connection Manager для динамічного управління підключеннями
- [ ] Налаштувати автоматичну синхронізацію конфігурацій (DO → Contabo)
- [ ] Інтегрувати DigitalOcean API для автоматичного масштабування
- [ ] Налаштувати автоматичне масштабування на основі навантаження
- [ ] Протестувати синхронізацію коду та конфігурацій
- [ ] Створити VPC на DigitalOcean та налаштувати Private Network
- [ ] Налаштувати VPN tunnel між Contabo та DO серверами
- [ ] Встановити та налаштувати HashiCorp Vault на DO Droplet 3
- [ ] Ініціалізувати Vault та зберегти unseal keys в secure storage
- [ ] Налаштувати Vault policies та AppRole authentication
- [ ] Мігрувати всі секрети з .env файлів в Vault
- [ ] Інтегрувати Vault з w100n_core (Go client)
- [ ] Налаштувати автоматичну ротацію паролів БД через Vault
- [ ] Налаштувати backup Vault storage backend
- [ ] Перевірити що .env файли більше не містять секретів
- [ ] Налаштувати firewall rules на всіх серверах
- [ ] Налаштувати автоматичні backups на DO Managed Databases (вбудовані)
- [ ] Налаштувати backup retention: 6 років для PHI (HIPAA), 30 днів для non-PHI
- [ ] Налаштувати географічне розподілення backups (3 локації для HIPAA)
- [ ] Налаштувати синхронізацію медіа файлів на CDN
- [ ] Протестувати відновлення з backup (щомісяця)
- [ ] Налаштувати централізоване логування (Loki + Grafana на DO Droplet 3)
- [ ] Налаштувати distributed tracing (Jaeger на DO Droplet 3)
- [ ] Налаштувати Prometheus + Grafana для метрик (на DO Droplet 3)
- [ ] Налаштувати alerting rules та notification channels
- [ ] Створити CI/CD pipeline (GitHub Actions)
- [ ] Налаштувати blue-green deployment
- [ ] Налаштувати connection pooling для DO Managed PostgreSQL (вбудований, перевірити параметри в DO панелі)
- [ ] Redis вже на Contabo Server 1 (основне навантаження)
- [ ] Налаштувати CDN (Cloudflare) для статики
- [ ] Налаштувати cost monitoring та alerts
- [ ] Підписати BAA з DigitalOcean та Contabo
- [ ] Налаштувати шифрування даних (at rest: disk encryption для PostgreSQL, WiredTiger для MongoDB; in transit: TLS 1.3)
- [ ] Налаштувати audit logging для HIPAA compliance
- [ ] Провести risk assessment та створити план зменшення ризиків
- [ ] Створити incident response plan
- [ ] Провести training персоналу по HIPAA
- [ ] Налаштувати регулярні security scans
- [ ] Запланувати penetration testing (щорічно)
- [ ] Налаштувати failback процедуру (повернення з Contabo на DO Primary)
- [ ] Налаштувати scaling down процедуру (вимкнення Contabo після нормалізації навантаження)
- [ ] Документувати network topology (VPC, VPN, IP ranges)
- [ ] Створити архітектурну діаграму з усіма компонентами