# API Security Analyzer

> **Проект реализован в рамках хакатона VTB API 2025**  
> **Трек "Защита API: автоматический анализ уязвимостей"**

**Команда 200 OK:**
- **Лютов Вадим** - Backend Developer | [@VadimUpdate](https://github.com/VadimUpdate)
- **Полина Цуканова** - Frontend Developer | [@polexka](https://github.com/polexka/)
- **Алексей Борисов** - Security Engineer | [@alertcollaps](https://github.com/alertcollaps)
- **Александр Сибриков** - Project Manager | [@Al78x](https://github.com/Al78x)

---

## 🎯 О проекте

Инструмент для автоматического анализа безопасности REST API на основе OpenAPI спецификации. Решение разработано для борьбы с ключевыми проблемами безопасности современных API:

### Проблематика
Современные API — это основа цифровых сервисов, но их рост и усложнение приводят к увеличению числа уязвимостей, которые часто выявляются слишком поздно — уже после инцидентов. Типичные проблемы:

- **Ручная проверка безопасности** — медленная, дорогая и подвержена человеческому фактору
- **Отсутствие автоматизированного анализа** соответствия API его контракту (OpenAPI/Swagger)
- **Недостаточная защита от OWASP API Top 10** угроз (BOLA, инъекции, слабая аутентификация и т.д.)
- **Нет единого инструмента**, объединяющего статический анализ, динамическое тестирование и валидацию контракта

### Решение
Автоматизированный инструмент анализа безопасности и корректности API, который:

- ✅ **Работает в один клик** или в автоматическом режиме (CI/CD)
- ✅ **Анализирует спецификации OpenAPI** и реальное поведение API
- ✅ **Выявляет уязвимости из OWASP API Top 10**
- ✅ **Проверяет соответствие поведения API** его контракту
- ✅ **Предоставляет понятный отчет** с рекомендациями по устранению проблем
- ✅ **Интегрируется в DevOps-процессы**

## 🚀 Быстрый старт

### Запуск приложения

1. **Клонируйте репозиторий:**
   ```bash
   git clone https://github.com/VadimUpdate/api-security-analyzer.git
   cd api-security-analyzer
   ```

2. **Запустите приложение:**
   ```bash
   ./gradlew bootrun
   ```

Приложение будет доступно по адресу: `http://localhost:8080`

### Проверка работы

Используйте **Postman** или любой другой HTTP-клиент для тестирования:

**Метод:** `POST`  
**URL:** `http://localhost:8080/api/analyze`  
**Content-Type:** `application/json`

**Тело запроса (Body):**
```json
{
  "specUrl": "https://vbank.open.bankingapi.ru/openapi.json",
  "targetUrl": "https://vbank.open.bankingapi.ru", 
  "maxConcurrency": 6,
  "politenessDelayMs": 150,
  "authClientId": "<team_name>",
  "authClientSecret": "<secret_key>",
  "enableFuzzing": true
}
```

## 📊 Пример ответа

После успешного анализа вы получите отчет в формате JSON:

```json
{
  "specUrl": "https://vbank.open.bankingapi.ru/openapi.json",
  "targetUrl": "https://vbank.open.bankingapi.ru",
  "timestamp": "2025-11-01T08:17:13.742153300Z",
  "totalEndpoints": 154,
  "summary": {
    "totalIssues": 71,
    "issuesByType": {
      "AUTH_TOKEN_FAIL": 1,
      "BOLA": 9,
      "IDOR": 7,
      "ENDPOINT_ERROR_STATUS": 20,
      "BROKEN_AUTH": 3,
      "RATE_LIMITING": 24,
      "XSS": 1,
      "PATH_TRAVERSAL": 1,
      "EXCESSIVE_DATA_EXPOSURE": 2,
      "SECURITY_MISCONFIGURATION": 2,
      "PUBLIC_API_DOCS": 1
    },
    "uniqueEndpoints": 22
  },
  "issues": [
    {
      "type": "AUTH_TOKEN_FAIL",
      "severity": "HIGH",
      "description": "Не удалось получить токен автоматически"
    },
    {
      "type": "BOLA",
      "severity": "MEDIUM", 
      "description": "Публичный доступ к ресурсу с идентификатором — потенциальная BOLA, HTTP 200",
      "path": "https://vbank.open.bankingapi.ru/accounts/60",
      "method": "GET",
      "evidence": "HTTP 200"
    },
    {
      "type": "IDOR", 
      "severity": "HIGH",
      "description": "Возможный IDOR через числовой ID в URL",
      "path": "https://vbank.open.bankingapi.ru/accounts/60",
      "method": "GET",
      "evidence": "Проверьте изменение ID"
    }
    // ... остальные issues
  ]
}
```

## 🛠 Параметры запроса

| Параметр | Тип | Обязательный | Описание |
|----------|-----|--------------|-----------|
| `specUrl` | string | Да | URL OpenAPI спецификации |
| `targetUrl` | string | Да | Базовый URL тестируемого API |
| `maxConcurrency` | number | Нет | Максимальное количество одновременных запросов (по умолчанию: 5) |
| `politenessDelayMs` | number | Нет | Задержка между запросами в миллисекундах (по умолчанию: 100) |
| `authClientId` | string | Нет | Client ID для OAuth аутентификации |
| `authClientSecret` | string | Нет | Client Secret для OAuth аутентификации |
| `enableFuzzing` | boolean | Нет | Включить фаззинг-тесты (по умолчанию: false) |

## 🛡 Обнаруживаемые уязвимости

- **BOLA** (Broken Object Level Authorization)
- **IDOR** (Insecure Direct Object References) 
- **Broken Authentication** (Небезопасная аутентификация)
- **Rate Limiting** (Отсутствие ограничения частоты запросов)
- **XSS** (Cross-Site Scripting)
- **Path Traversal** (Обход пути)
- **Excessive Data Exposure** (Избыточное раскрытие данных)
- **Security Misconfiguration** (Небезопасные настройки)
- **Public API Documentation** (Публичная документация API)

## 🎯 Функциональные возможности

### ✅ Реализовано
- **Анализ уязвимостей OWASP API Top 10** (BOLA, IDOR, инъекции, слабая аутентификация и др.)
- **Валидация контракта API** - сравнение фактического поведения со спецификацией
- **Интеграция через REST API** - простой запуск анализа
- **Поддержка OpenAPI 3.1+, Swagger 2.0**
- **Фаззинг-тесты** - генерация нестандартных запросов
- **Автоматическая аутентификация** (OAuth2)
- **Детальная отчетность** в JSON формате

### 🔮 Дополнительные возможности
- **Высокая скорость анализа** - ≤5 минут для 20-30 эндпоинтов
- **Модульная архитектура** - возможность подключения новых проверок
- **Обнаружение "открытых дверей"** - эндпоинтов без аутентификации, debug-интерфейсов

---

*Разработано в рамках хакатона VTB API 2025 | Команда 200 OK*
```
