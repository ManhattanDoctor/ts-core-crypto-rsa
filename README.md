# @ts-core/crypto-rsa

TypeScript библиотека для асимметричного шифрования и цифровых подписей с использованием алгоритма RSA.

[![NPM Version](https://img.shields.io/npm/v/@ts-core/crypto-rsa.svg)](https://www.npmjs.com/package/@ts-core/crypto-rsa)
[![License](https://img.shields.io/npm/l/@ts-core/crypto-rsa.svg)](https://github.com/ManhattanDoctor/ts-core-crypto-rsa/blob/main/LICENSE)

## Описание

Библиотека предоставляет простой и удобный API для работы с криптографическими операциями RSA:

- Генерация пар ключей (публичного и приватного)
- Шифрование сообщений публичным ключом
- Расшифровка сообщений приватным ключом
- Создание цифровых подписей
- Верификация подписей

Также включает интеграцию с транспортным слоем `@ts-core/common` для подписи и верификации команд.

## Установка

```bash
npm install @ts-core/crypto-rsa
```

или

```bash
yarn add @ts-core/crypto-rsa
```

## Требования

- Node.js >= 14
- TypeScript >= 4.0 (опционально)

## Быстрый старт

```typescript
import { RSA } from '@ts-core/crypto-rsa';

// Генерация пары ключей
const keys = RSA.keys();
console.log('Public Key:', keys.publicKey);
console.log('Private Key:', keys.privateKey);

// Шифрование и расшифровка
const message = 'Hello, World!';
const encrypted = RSA.encrypt(message, keys.publicKey);
const decrypted = RSA.decrypt(encrypted, keys.privateKey);
console.log('Decrypted:', decrypted); // 'Hello, World!'

// Подпись и верификация
const signature = RSA.sign(message, keys.privateKey);
const isValid = RSA.verify(message, signature, keys.publicKey);
console.log('Signature valid:', isValid); // true
```

## API

### Класс `RSA`

Статический класс для выполнения криптографических операций RSA.

#### Константы

| Имя | Тип | Значение | Описание |
|-----|-----|----------|----------|
| `ALGORITHM` | `string` | `'RSA'` | Идентификатор алгоритма |

#### Методы

##### `RSA.keys(bits?: number, exponent?: number): IKeyAsymmetric`

Генерирует пару RSA ключей.

**Параметры:**

| Параметр | Тип | По умолчанию | Описание |
|----------|-----|--------------|----------|
| `bits` | `number` | `2048` | Размер ключа в битах |
| `exponent` | `number` | `65537` | Публичный экспонент |

**Возвращает:** Объект с полями `publicKey` и `privateKey` в формате PEM (PKCS#8).

**Пример:**

```typescript
// Ключ по умолчанию (2048 бит)
const keys = RSA.keys();

// Усиленный ключ (4096 бит)
const strongKeys = RSA.keys(4096);

// Кастомная конфигурация
const customKeys = RSA.keys(2048, 65537);
```

---

##### `RSA.encrypt(message: string, publicKey: string): string`

Шифрует сообщение публичным ключом.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `message` | `string` | Сообщение для шифрования |
| `publicKey` | `string` | Публичный ключ в формате PEM |

**Возвращает:** Зашифрованное сообщение в hex-формате.

**Пример:**

```typescript
const encrypted = RSA.encrypt('Секретное сообщение', keys.publicKey);
// Результат: 'a1b2c3d4e5f6...' (hex-строка)
```

---

##### `RSA.decrypt(message: string, privateKey: string): string`

Расшифровывает сообщение приватным ключом.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `message` | `string` | Зашифрованное сообщение (hex) |
| `privateKey` | `string` | Приватный ключ в формате PEM |

**Возвращает:** Расшифрованное сообщение.

**Пример:**

```typescript
const decrypted = RSA.decrypt(encrypted, keys.privateKey);
// Результат: 'Секретное сообщение'
```

---

##### `RSA.sign(message: string, privateKey: string): string`

Создает цифровую подпись сообщения.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `message` | `string` | Сообщение для подписи |
| `privateKey` | `string` | Приватный ключ в формате PEM |

**Возвращает:** Подпись в hex-формате.

**Пример:**

```typescript
const signature = RSA.sign('Важный документ', keys.privateKey);
```

---

##### `RSA.verify(message: string, signature: string, publicKey: string): boolean`

Проверяет цифровую подпись сообщения.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `message` | `string` | Исходное сообщение |
| `signature` | `string` | Подпись (hex) |
| `publicKey` | `string` | Публичный ключ в формате PEM |

**Возвращает:** `true` если подпись верна, `false` в противном случае.

**Пример:**

```typescript
const isValid = RSA.verify('Важный документ', signature, keys.publicKey);
if (isValid) {
    console.log('Подпись подтверждена');
}
```

---

### Класс `TransportCryptoManagerRSA`

Менеджер для криптографических операций над транспортными командами. Расширяет `TransportCryptoManager` из `@ts-core/common`.

#### Константы

| Имя | Тип | Значение | Описание |
|-----|-----|----------|----------|
| `ALGORITHM` | `string` | `'RSA'` | Идентификатор алгоритма |

#### Свойства

| Имя | Тип | Описание |
|-----|-----|----------|
| `algorithm` | `string` | Возвращает `'RSA'` |

#### Методы

##### `sign<U>(command: ITransportCommand<U>, nonce: string, privateKey: string): Promise<string>`

Подписывает транспортную команду.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `command` | `ITransportCommand<U>` | Команда для подписи |
| `nonce` | `string` | Уникальный идентификатор (для защиты от replay-атак) |
| `privateKey` | `string` | Приватный ключ |

**Возвращает:** `Promise<string>` — подпись команды.

---

##### `verify<U>(command: ITransportCommand<U>, signature: ISignature): Promise<boolean>`

Проверяет подпись транспортной команды.

**Параметры:**

| Параметр | Тип | Описание |
|----------|-----|----------|
| `command` | `ITransportCommand<U>` | Команда для проверки |
| `signature` | `ISignature` | Объект подписи (value, nonce, publicKey) |

**Возвращает:** `Promise<boolean>` — результат верификации.

---

#### Пример использования

```typescript
import { TransportCryptoManagerRSA, RSA } from '@ts-core/crypto-rsa';

const cryptoManager = new TransportCryptoManagerRSA();
const keys = RSA.keys();

// Подпись команды
const command = { name: 'UserCreate', request: { username: 'john' } };
const nonce = Date.now().toString();
const signature = await cryptoManager.sign(command, nonce, keys.privateKey);

// Верификация команды
const isValid = await cryptoManager.verify(command, {
    value: signature,
    nonce: nonce,
    publicKey: keys.publicKey
});
```

## Формат ключей

Библиотека использует формат PEM (PKCS#8):

**Публичный ключ:**
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
```

**Приватный ключ:**
```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEA...
-----END PRIVATE KEY-----
```

## Рекомендации по безопасности

1. **Размер ключа**: Используйте минимум 2048 бит для production. Для повышенной безопасности — 4096 бит.

2. **Хранение приватных ключей**: Никогда не храните приватные ключи в открытом виде. Используйте:
   - Переменные окружения
   - Системы управления секретами (Vault, AWS Secrets Manager)
   - HSM (Hardware Security Modules)

3. **Защита от replay-атак**: При использовании `TransportCryptoManagerRSA` всегда используйте уникальный `nonce`.

4. **Ограничение размера сообщений**: RSA может шифровать сообщения ограниченного размера (зависит от длины ключа). Для больших данных используйте гибридное шифрование.

## Примеры использования

### Безопасный обмен сообщениями

```typescript
import { RSA } from '@ts-core/crypto-rsa';

// Алиса генерирует ключи и публикует публичный ключ
const aliceKeys = RSA.keys();
const alicePublicKey = aliceKeys.publicKey;

// Боб шифрует сообщение для Алисы
const secretMessage = 'Встречаемся в полночь';
const encryptedForAlice = RSA.encrypt(secretMessage, alicePublicKey);

// Алиса расшифровывает сообщение
const decryptedMessage = RSA.decrypt(encryptedForAlice, aliceKeys.privateKey);
console.log(decryptedMessage); // 'Встречаемся в полночь'
```

### Верификация документов

```typescript
import { RSA } from '@ts-core/crypto-rsa';

// Автор подписывает документ
const authorKeys = RSA.keys();
const document = JSON.stringify({ title: 'Контракт', amount: 1000 });
const documentSignature = RSA.sign(document, authorKeys.privateKey);

// Публикуем: document, documentSignature, authorKeys.publicKey

// Любой может проверить подлинность
const isAuthentic = RSA.verify(document, documentSignature, authorKeys.publicKey);
if (isAuthentic) {
    console.log('Документ подлинный и не был изменен');
}
```

### Интеграция с API

```typescript
import { TransportCryptoManagerRSA, RSA } from '@ts-core/crypto-rsa';

class SecureApiClient {
    private cryptoManager = new TransportCryptoManagerRSA();
    private privateKey: string;

    constructor(privateKey: string) {
        this.privateKey = privateKey;
    }

    async sendCommand(command: any) {
        const nonce = crypto.randomUUID();
        const signature = await this.cryptoManager.sign(command, nonce, this.privateKey);

        return fetch('/api/command', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                command,
                signature: {
                    value: signature,
                    nonce,
                    algorithm: this.cryptoManager.algorithm
                }
            })
        });
    }
}
```

## Совместимость модулей

Библиотека поддерживает оба формата модулей:

- **CommonJS**: `require('@ts-core/crypto-rsa')`
- **ES Modules**: `import { RSA } from '@ts-core/crypto-rsa'`

## Зависимости

| Пакет | Версия | Описание |
|-------|--------|----------|
| `@ts-core/common` | ~3.0.57 | Базовые интерфейсы и классы |
| `node-rsa` | ^1.1.1 | RSA криптография для Node.js |

## Связанные пакеты

- [@ts-core/common](https://www.npmjs.com/package/@ts-core/common) — базовая библиотека
- [@ts-core/crypto-gost](https://www.npmjs.com/package/@ts-core/crypto-gost) — ГОСТ криптография

## Лицензия

ISC

## Автор

**Renat Gubaev** — [renat.gubaev@gmail.com](mailto:renat.gubaev@gmail.com)

## Содействие

1. Fork репозитория
2. Создайте feature branch (`git checkout -b feature/amazing-feature`)
3. Commit изменения (`git commit -m 'Add amazing feature'`)
4. Push в branch (`git push origin feature/amazing-feature`)
5. Откройте Pull Request
