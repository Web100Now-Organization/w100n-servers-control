# Тестування WebSocket в Postman

## Покрокова інструкція

### 1. Відкрийте WebSocket в Postman

1. Відкрийте Postman
2. Натисніть "New" → "WebSocket Request"
3. Введіть URL: `ws://localhost:8082/api/platform/v1`
4. Натисніть "Connect"

### 2. Ініціалізуйте з'єднання

Надішліть перше повідомлення:

```json
{"type":"connection_init"}
```

Очікувана відповідь:
```json
{"type":"connection_ack"}
```

### 3. Підпишіться на subscription

Спочатку запустіть mutation для створення setup:

```graphql
mutation {
  startServerSetup(
    serverIP: "192.168.1.37"
    serverPort: 22
    username: "maksym"
    password: "Max10223"
  ) {
    success
    message
    setupId
  }
}
```

Після отримання `setupId`, надішліть subscription:

```json
{
  "id": "1",
  "type": "subscribe",
  "payload": {
    "query": "subscription { serverSetupProgress(setupId: \"YOUR_SETUP_ID_HERE\") { step totalSteps message status error timestamp } }"
  }
}
```

### 4. Отримуйте оновлення

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
        "timestamp": 1766106851
      }
    }
  }
}
```

### 5. Завершення

Коли setup завершиться, ви отримаєте:

```json
{
  "id": "1",
  "type": "complete"
}
```

## Альтернатива: Використання Altair GraphQL Client

Altair краще підтримує GraphQL subscriptions через WebSocket:

1. Встановіть [Altair GraphQL Client](https://altairgraphql.dev/)
2. Введіть URL: `ws://localhost:8082/api/platform/v1`
3. Виберіть вкладку "Subscriptions"
4. Введіть subscription запит:

```graphql
subscription {
  serverSetupProgress(setupId: "YOUR_SETUP_ID_HERE") {
    step
    totalSteps
    message
    status
    error
    timestamp
  }
}
```

5. Натисніть "Start subscription"

## Відлагодження

Якщо виникають проблеми:

1. Перевірте логи сервера - всі етапи логуються в консоль
2. Перевірте, чи правильний протокол (`graphql-transport-ws`, не `graphql-ws`)
3. Переконайтеся, що middleware не блокує WebSocket connection
4. Перевірте, чи `setupId` існує (він зберігається в пам'яті під час виконання setup)

## Підтримка протоколів

gqlgen автоматично підтримує обидва протоколи:
- `graphql-transport-ws` (новий, рекомендований)
- `graphql-ws` (legacy, для сумісності)

Postman може використовувати обидва, але краще використовувати `graphql-transport-ws`.

