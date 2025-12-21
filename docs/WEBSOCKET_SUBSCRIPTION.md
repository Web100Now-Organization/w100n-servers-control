# WebSocket Subscription для Server Setup

## ✅ WebSocket налаштовано!

WebSocket transport для GraphQL subscriptions тепер налаштовано в `core/api/router.go`. gqlgen автоматично обробляє WebSocket підключення через протокол `graphql-transport-ws`.

## ⚠️ Важливо для Postman

**Postman НЕ підтримує автоматично протокол `graphql-transport-ws`!**

Ви **НЕ можете** просто надіслати raw GraphQL subscription запит. Потрібно використовувати правильний формат протоколу.

**Див. детальну інструкцію:** [`WEBSOCKET_POSTMAN_STEP_BY_STEP.md`](./WEBSOCKET_POSTMAN_STEP_BY_STEP.md)

## Правильний формат для WebSocket Subscription

### Протокол: graphql-transport-ws

gqlgen використовує протокол `graphql-transport-ws` (не старий `graphql-ws`). Протокол потребує наступного формату повідомлень:

#### 1. Підключення до WebSocket

```
ws://localhost:8082/api/platform/v1
```

#### 2. Ініціалізація з'єднання (Connection Init)

```json
{
  "type": "connection_init"
}
```

Сервер повинен відповісти:

```json
{
  "type": "connection_ack"
}
```

#### 3. Підписка на subscription

```json
{
  "id": "1",
  "type": "subscribe",
  "payload": {
    "query": "subscription { serverSetupProgress(setupId: \"setup-1766106851324338000\") { step totalSteps message status error timestamp } }"
  }
}
```

**Примітка:** У протоколі `graphql-transport-ws` використовується тип `subscribe`, а не `start`.

#### 4. Отримання повідомлень

Сервер поверне повідомлення типу `next`:

```json
{
  "id": "1",
  "type": "next",
  "payload": {
    "data": {
      "serverSetupProgress": {
        "step": 1,
        "totalSteps": 17,
        "message": "Updating system packages...",
        "status": "running",
        "timestamp": 1766106851
      }
    }
  }
}
```

#### 5. Завершення підписки

Коли subscription завершиться:

```json
{
  "id": "1",
  "type": "complete"
}
```

### Різниця між протоколами

- **graphql-transport-ws** (новий, використовується gqlgen):
  - `type: "connection_init"` → `connection_ack`
  - `type: "subscribe"` → `next` → `complete`
  
- **graphql-ws** (старий):
  - `type: "connection_init"` → `connection_ack`
  - `type: "start"` → `data` → `complete`

### Варіант 3: Використання GraphQL клієнта

Для тестування краще використовувати GraphQL клієнти, які підтримують WebSocket:
- GraphQL Playground
- Altair GraphQL Client
- Apollo Studio
- Insomnia (з GraphQL plugin)

## Альтернатива: Перевірка логів у консолі

Поки WebSocket не налаштований, всі етапи налаштування сервера тепер логуються в консоль:

```
[ServerSetup] Step 1/17 [running] Updating system packages...
[ServerSetup] Step 1/17 [completed] System updated successfully
[ServerSetup] Step 2/17 [running] Installing essential packages...
[ServersControl] Progress update [setup-xxx] Step 2/17: Installing essential packages...
...
```

Всі логи з префіксом `[ServerSetup]` та `[ServersControl]` показують прогрес налаштування сервера.

## Приклад використання в коді

```go
// У setup.go додано логи:
log.Printf("[ServerSetup] Step %d/%d [%s] %s", step, totalSteps, status, message)

// У resolvers.go додано логи:
logger.LogInfo(fmt.Sprintf("[ServersControl] Progress update [%s] Step %d/%d: %s", ...))
```

## Налаштування Postman WebSocket

Якщо хочете використовувати Postman WebSocket:

1. Відкрийте новий WebSocket запит
2. URL: `ws://localhost:8082/api/platform/v1`
3. Надсилайте повідомлення в правильному форматі (див. Варіант 2 вище)

**Примітка:** Postman може не підтримувати повністю протокол `graphql-ws`. Рекомендується використовувати спеціалізовані GraphQL клієнти.

