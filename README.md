

Пример запроса в Postman 


POST http://195.2.73.25:8080/api/analyze

{
  "specUrl": "https://raw.githubusercontent.com/VadimUpdate/jsonSpec/refs/heads/main/bankenpoints",
  "targetUrl": "https://api.bankingapi.ru/api/rb/pmnt/acceptance/mobile/hackathon/v1",
  "clientId": "{YourClientId}",
  "clientSecret": "{YourClientSecret}",
  "requestingBank": "{YourRequestingBank}",
  "enableFuzzing": true,
  "enableBOLA": true,
  "enableBrokenAuth": true,
  "enableSpecChecks": true,
  "enableRateLimiting": true,
  "enableMassAssignment": true,
  "enableInjection": true,
  "enableSensitiveFiles": true,
  "enablePublicSwagger": true,
  "enableIDOR": true
}
