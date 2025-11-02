```markdown
# QNavi

QNavi — простий HTTP/HTTP3 сервіс на Rust з мінімальною реалізацією аутентифікації через JWT (access + refresh tokens) та базовим логуванням. Цей README описує, як запускати сервер, які змінні середовища потрібні, та деталі API (маршрути, формати запитів/відповідей).

Мова документації: українська.

## Коротко про проєкт

- Сервер слухає QUIC/HTTP3 (за допомогою quinn + h3 + h3-quinn), але логіка маршрутів написана у звичайному http-стилі.
- Аутентифікація:
  - access token — JWT з коротким TTL (за замовчуванням 15 хв).
  - refresh token — JWT з довшим TTL (за замовчуванням 30 днів). Refresh токени зберігаються в пам'яті у структурі сесій і при роуті `/refresh` відбувається їх ротація.
- Логування: tracing, debug/info для запитів та відповідей. Додаткові діагностичні логи при проблемах з токенами або повільною генерацією.

> Увага: це POC / демо. Не використовуйте як є у production — див. розділ Безпека.

---

## Залежності / складання

Файли проекту вже містять необхідні залежності у `Cargo.toml` (jsonwebtoken, rand, quinn, h3, dotenvy тощо).

Щоб зібрати:
1. Встановіть Rust (stable).
2. Переконайтесь, що у Cargo.toml присутні відповідні залежності.
3. Складання:
   ```
cargo build --release
   ```

Запуск у режимі розробки:
```
RUST_LOG=debug cargo run
```

---

## Змінні середовища

- `SECRET_KEY` — секрет для підпису HS256 JWT. Рекомендовано: 32+ байт у base64/hex або звичайний довільний рядок. Якщо відсутній — сервер згенерує тимчасовий секрет при старті (tokens не переживуть рестарт).
- `CERT_PATH` — (опціонально) шлях до PEM-файлу сертифікатів (може містити кілька `CERTIFICATE` блоків).
- `KEY_PATH` — (опціонально) шлях до PEM-файлу з приватним ключем (PKCS8 / PKCS1 / SEC1).
- Якщо `CERT_PATH` / `KEY_PATH` не задані — сервер створить тимчасовий self-signed сертифікат для локальної розробки.

Покрокова рекомендація:
1. Створіть `.env` з SECRET_KEY (наприклад):
   ```
SECRET_KEY=supersecret1234567890supersecret
   ```
2. (Опціонально) додайте CERT_PATH і KEY_PATH.

---

## API — маршрути

Усі запити/відповіді використовують `application/json`. Сервер логуватиме метод, шлях, заголовки та тіло запиту.

Базовий список маршрутів:
- POST /register
- POST /login
- POST /refresh
- POST /logout
- GET /profile

Далі — підробиці кожного.

### POST /register
Реєстрація нового користувача (POC — паролі зберігаються в явному вигляді, замініть на bcrypt/argon2 у production).

- Request (application/json):
  ```
{
"username": "alice",
"password": "pass"
}
  ```
- Response:
  - 201 Created
    ```
    {
      "id": "<uuid>",
      "username": "alice"
    }
    ```
  - 409 Conflict (якщо користувач існує)
    ```
    { "error": "user exists" }
    ```
  - 400 Bad Request (некоректний JSON)

### POST /login
Аутентифікація. Повертає пару токенів: access та refresh.

- Request:
  ```
{
"username": "alice",
"password": "pass"
}
  ```
- Response:
  - 200 OK
    ```
    {
      "access_token": "<jwt_access>",
      "refresh_token": "<jwt_refresh>"
    }
    ```
    Access — підписаний JWT (HS256), TTL ~15 хв (за замовчуванням).  
    Refresh — підписаний JWT з полем `jti`, TTL ~30 днів. Refresh зберігається у внутрішньому store.
  - 401 Unauthorized
    ```
    { "error": "invalid credentials" }
    ```

Примітка: сервіс формує JSON через serde_json::json!() та повертає як рядок з Content-Type: application/json.

### POST /refresh
Ротація refresh token → повертає нові access + refresh токени.

- Request:
  ```
{
"refresh_token": "<jwt_refresh>"
}
  ```
- Response:
  - 200 OK
    ```
    { "access_token": "<new_access>", "refresh_token": "<new_refresh>" }
    ```
  - 400 Bad Request — відсутнє поле / некоректний JSON
  - 401 Unauthorized — недійсний refresh токен або сесія не знайдена
    ```
    { "error": "invalid refresh token" }
    ```
  - 401 Unauthorized (якщо сесія не знайдена у store)
    ```
    { "error": "invalid refresh session" }
    ```

Реалізація:
- Сервер валідує підпис refresh JWT (HS256 з SECRET_KEY) та перевіряє `jti` у store.sessions.
- Щоб уникнути deadlock-ів, операція генерації нових токенів виконується поза `write`-замком: під lock читається user_id/jti, lock звільняється, генеруються токени, після чого коротко береться `write` щоб оновити/замінити сесію.

### POST /logout
Відкликання refresh токена (видалення з store).

- Request:
  ```
{ "refresh_token": "<jwt_refresh>" }
  ```
- Response:
  - 200 OK
    ```
    { "ok": true }
    ```
  - 404 Not Found
    ```
    { "error": "refresh token not found" }
    ```

### GET /getprofile, /profile, /me
Отримати профіль поточного користувача. Потрібен заголовок:
```
Authorization: Bearer <access_token>
```

- Response:
  - 200 OK
    ```
    {
      "id": "<uuid>",
      "username": "alice",
      "created_at": "<iso datetime>"
    }
    ```
  - 401 Unauthorized
    ```
    { "error": "invalid access token" }
    ```

---

## Формат JWT (claims)

- AccessClaims:
  ```
{
"sub": "<user_id>", // UUID as string
"exp": <expiry_unix_ts>,
"iat": <issued_at_unix_ts>
}
  ```

- RefreshClaims:
  ```
{
"sub": "<user_id>",
"exp": <expiry_unix_ts>,
"iat": <issued_at_unix_ts>,
"jti": "<random id>"
}
  ```

Підпис: HS256 (jsonwebtoken crate) з секретом `SECRET_KEY`.

---

## Логування та діагностика

- Використовується `tracing` + `tracing-subscriber`.
- Для відлагодження запускайте зі змінною:
  ```
RUST_LOG=debug cargo run
  ```
- Сервер логує:
  - Вхідні запити (method, path) — info
  - Заголовки та тіло запиту — debug
  - Повертання JSON — info
  - Додаткові діагностичні повідомлення при проблемах з токенами / повільною генерацією.

---

## Важливі зауваження щодо безпеки / production notes

- Паролі не хешуються — замініть на argon2/bcrypt у production.
- Store.sessions та користувачі зберігаються в пам'яті — при рестарті всі сесії зникнуть. Для production використовуйте Redis або БД.
- SECRET_KEY має бути конфіденційним. Зберігайте у секретному сховищі (KMS/Vault) або як secret в середовищі виконання.
- Розгляньте використання більш надійної політики ротації refresh токенів або реєстрації пристроїв.
- Можна перейти на RS256/ES256 і зберігати відкритий ключ у валідаційних сервісах, якщо потрібно розділення підписувача й валідації.

---

## Тестові приклади з curl

1) Register
```
curl -X POST https://localhost:4433/register \
-H "Content-Type: application/json" \
-d '{"username":"alice","password":"pass"}'
```

2) Login
```
curl -X POST https://localhost:4433/login \
-H "Content-Type: application/json" \
-d '{"username":"alice","password":"pass"}'
```

3) Get profile
```
curl -X GET https://localhost:4433/getprofile \
-H "Authorization: Bearer <access_token>"
```

4) Refresh
```
curl -X POST https://localhost:4433/refresh \
-H "Content-Type: application/json" \
-d '{"refresh_token":"<refresh_token>"}'
```

5) Logout
```
curl -X POST https://localhost:4433/logout \
-H "Content-Type: application/json" \
-d '{"refresh_token":"<refresh_token>"}'
```

---

## Дальші кроки (рекомендації)

- Заміна сховища сесій на Redis / БД (щоб токени не губилися при рестарті).
- Хешування паролів (argon2).
- Поліпшення політики ротації refresh токенів (одноразові refresh tokens).
- Документувати OpenAPI/Swagger для зовнішніх клієнтів.
- Додати інтеграційні тести для ендпоінтів.

Якщо хочете — можу:
- Згенерувати OpenAPI (Swagger) на основі реалізованих ендпоінтів.
- Автоматично вкинути цей README у репозиторій як commit/PR (потрібен дозвіл/інформація про репозиторій).
- Додати приклади клієнта на curl / httpie / JavaScript.
```