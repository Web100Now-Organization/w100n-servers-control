# Покрокова інструкція: WebSocket Subscription в Postman

## Проблема: "invalid json"

Postman надсилає raw GraphQL запит, але gqlgen використовує протокол **`graphql-transport-ws`**, який потребує специфічного формату повідомлень.

## ✅ Правильна послідовність кроків

### Крок 1: Підключення до WebSocket

1. Відкрийте Postman
2. Створіть новий **WebSocket Request**
3. URL: `ws://localhost:8082/api/platform/v1`
4. Натисніть **"Connect"**

### Крок 2: Ініціалізація з'єднання

**Надішліть перше повідомлення:**

```json
{"type":"connection_init"}
```

**Очікувана відповідь:**
```json
{"type":"connection_ack"}
```

Якщо ви отримали `connection_ack` - з'єднання успішне! ✅

### Крок 3: Запустіть Mutation (через HTTP POST, не WebSocket!)

**ВАЖЛИВО:** Mutation потрібно запускати через звичайний HTTP POST запит, а не через WebSocket!

1. Створіть новий **HTTP Request** в Postman
2. Метод: **POST**
3. URL: `http://localhost:8082/api/platform/v1`
4. Headers:
   - `Content-Type: application/json`
5. Body (raw JSON):

```json
{
  "query": "mutation StartServerSetup($serverIP: String!, $serverPort: Int!, $username: String!, $password: String!) { startServerSetup(serverIP: $serverIP, serverPort: $serverPort, username: $username, password: $password) { success message setupId } }",
  "variables": {
    "serverIP": "192.168.1.37",
    "serverPort": 22,
    "username": "maksym",
    "password": "Max10223"
  }
}
```

6. Натисніть **Send**
7. Скопіюйте `setupId` з відповіді (наприклад: `"setup-1766108037485225000"`)

### Крок 4: Підписка на Subscription (через WebSocket)

**Поверніться до WebSocket з'єднання** і надішліть:

```json
{
  "id": "1",
  "type": "subscribe",
  "payload": {
    "query": "subscription { serverSetupProgress(setupId: \"setup-1766108037485225000\") { step totalSteps message status error timestamp } }"
  }
}
```

**Замініть `setup-1766108037485225000` на ваш реальний setupId!**

### Крок 5: Отримання оновлень

Ви отримаєте повідомлення типу `next` кожного разу, коли змінюється прогрес:

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
        "timestamp": 1766108037
      }
    }
  }
}
```

### Крок 6: Завершення

Коли setup завершиться, ви отримаєте:

```json
{
  "id": "1",
  "type": "complete"
}
```

## ❌ Чого НЕ робити

1. **НЕ надсилайте raw GraphQL запит** без протоколу:
   ```json
   ❌ subscription { serverSetupProgress(...) { ... } }
   ```

2. **НЕ використовуйте тип `start`** (це старий протокол):
   ```json
   ❌ {"type": "start", ...}
   ```

3. **НЕ запускайте mutation через WebSocket** - використовуйте HTTP POST

## 🔍 Відлагодження

### Якщо отримуєте "invalid json":

1. Перевірте, чи ви надіслали `{"type":"connection_init"}` спочатку
2. Перевірте, чи ви отримали `{"type":"connection_ack"}` у відповідь
3. Переконайтеся, що використовуєте тип `subscribe`, а не `start`
4. Перевірте, чи JSON правильно форматується (без зайвих пробілів, правильні лапки)

### Альтернатива: Використання Altair GraphQL Client

Якщо Postman не працює, використовуйте **Altair GraphQL Client**:

1. Встановіть [Altair GraphQL Client](https://altairgraphql.dev/)
2. Введіть URL: `ws://localhost:8082/api/platform/v1`
3. Виберіть вкладку **"Subscriptions"**
4. Введіть subscription запит
5. Натисніть **"Start subscription"**

Altair автоматично обробляє протокол `graphql-transport-ws`.

## 📝 Приклад повної сесії

```
1. Connect: ws://localhost:8082/api/platform/v1
2. Send: {"type":"connection_init"}
3. Receive: {"type":"connection_ack"}
4. (HTTP POST) Start mutation → отримати setupId
5. Send: {"id":"1","type":"subscribe","payload":{"query":"subscription { serverSetupProgress(setupId: \"YOUR_ID\") { step message status } }"}}
6. Receive: {"id":"1","type":"next","payload":{"data":{"serverSetupProgress":{...}}}}
7. Receive: {"id":"1","type":"complete"}
```

## 💡 Порада

Поки ви налаштовуєте WebSocket, всі етапи налаштування сервера **логуються в консоль сервера**:

```
[ServerSetup] Step 1/17 [running] Updating system packages...
[ServerSetup] Step 1/17 [completed] System updated successfully
[ServersControl] Progress update [setup-xxx] Step 1/17: Updating system packages...
```

Ви можете відстежувати прогрес через логи, поки WebSocket не налаштований!

