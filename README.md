# Быстрый старт

git clone https://github.com/VadimUpdate/api-security-analyzer.git

cd api-security-analyzer    

./gradlew bootrun        


Проверка в Postman:

POST http://localhost:8080/api/analyze

Body

{
    "specUrl": "https://vbank.open.bankingapi.ru/openapi.json",
    "targetUrl": "https://vbank.open.bankingapi.ru",
    "maxConcurrency": 6,
    "politenessDelayMs": 150,
    "authClientId": "team186",
    "authClientSecret": "sSwEucZD6NXXi0eC0Fov7sFJD9iFKWOl",
    "enableFuzzing": true
}

Ответ должен быть примерно таким: 
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
        },
        {
            "type": "ENDPOINT_ERROR_STATUS",
            "severity": "LOW",
            "description": "Эндпоинт https://vbank.open.bankingapi.ru/accounts вернул HTTP 401",
            "path": "https://vbank.open.bankingapi.ru/accounts",
            "method": "GET",
            "evidence": "HTTP 401"
        },
        {
            "type": "BROKEN_AUTH",
            "severity": "HIGH",
            "description": "Эндпоинт доступен без токена",
            "path": "https://vbank.open.bankingapi.ru/accounts/60",
            "method": "GET",
            "evidence": "HTTP 200"
        },
        {
            "type": "RATE_LIMITING",
            "severity": "MEDIUM",
            "description": "Эндпоинт https://vbank.open.bankingapi.ru/accounts/60 не защищен rate limiting (можно слать много запросов)",
            "path": "https://vbank.open.bankingapi.ru/accounts/60",
            "method": "GET"
        },
        {
            "type": "RATE_LIMITING",
            "severity": "MEDIUM",
            "description": "Эндпоинт https://vbank.open.bankingapi.ru/accounts не защищен rate limiting (можно слать много запросов)",
            "path": "https://vbank.open.bankingapi.ru/accounts",
            "method": "GET"
        },
        {
            "type": "RATE_LIMITING",
            "severity": "MEDIUM",
            "description": "Эндпоинт https://vbank.open.bankingapi.ru/auth/bank-token не защищен rate limiting (можно слать много запросов)",
            "path": "https://vbank.open.bankingapi.ru/auth/bank-token",
            "method": "POST"
        },
        {
            "type": "RATE_LIMITING",
            "severity": "MEDIUM",
            "description": "Эндпоинт https://vbank.open.bankingapi.ru/accounts не защищен rate limiting (можно слать много запросов)",
            "path": "https://vbank.open.bankingapi.ru/accounts",
            "method": "POST"
        },
        {
            "type": "ENDPOINT_ERROR_STATUS",
            "severity": "LOW",
            "description": "Эндпоинт https://vbank.open.bankingapi.ru/accounts вернул HTTP 401 (требуется авторизация)",
            "path": "https://vbank.open.bankingapi.ru/accounts",
            "method": "GET",
            "evidence": "HTTP 401"
        },
        {
            "type": "BOLA",
            "severity": "MEDIUM",
            "description": "Публичный доступ к ресурсу с идентификатором — потенциальная BOLA, HTTP 200",
            "path": "https://vbank.open.bankingapi.ru/accounts/1/balances",
            "method": "GET",
            "evidence": "HTTP 200"
        }

        ...


