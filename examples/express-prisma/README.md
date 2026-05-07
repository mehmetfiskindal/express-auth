# Express + Prisma Auth Example with OpenAPI

Bu örnek, `@developersailor/express-auth` paketini Express, Prisma ve `@developersailor/express-openapi-decorators` ile kullanmayı gösterir.

## Özellikler

- 🔐 **JWT Authentication** - Access ve refresh token desteği
- 🔄 **Token Rotation** - Güvenli refresh token yönetimi
- 👤 **Role-based Access Control** - Admin/User rol yönetimi
- 📝 **OpenAPI/Swagger** - Tam otomatik API dokümantasyonu
- 🍪 **Cookie Support** - Güvenli httpOnly cookie desteği
- 🗄️ **Prisma ORM** - Type-safe database operations

## Kurulum

```bash
# Bağımlılıkları yükle
npm install

# Veritabanını oluştur
npx prisma migrate dev --name init

# Prisma client'ı üret
npx prisma generate

# (Opsiyonel) Seed veri ekle
npm run db:seed
```

## Çalıştırma

```bash
# Development
npm run dev

# Production
npm run build
node dist/index.js
```

## API Dokümantasyonu

Sunucu çalıştığında Swagger UI'a şu adreslerden erişebilirsiniz:

- **Swagger UI**: http://localhost:3000/api-docs
- **OpenAPI JSON**: http://localhost:3000/api-docs.json

## Test

### Register
```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

### Login
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

### Access Protected Endpoint
```bash
curl http://localhost:3000/api/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Refresh Token
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "YOUR_REFRESH_TOKEN"}'
```

### Logout
```bash
curl -X POST http://localhost:3000/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "YOUR_REFRESH_TOKEN"}'
```

## Proje Yapısı

```
.
├── prisma/
│   ├── schema.prisma              # Database schema
│   └── seed.ts                    # Seed data
├── src/
│   ├── controllers/
│   │   ├── auth.controller.ts     # Auth controller with OpenAPI decorators
│   │   └── profile.controller.ts  # Profile controller
│   ├── dto/
│   │   ├── auth.dto.ts            # Auth request/response DTOs
│   │   └── profile.dto.ts         # Profile DTOs
│   ├── repositories/
│   │   ├── prisma-user.repository.ts        # User repository implementation
│   │   └── prisma-refresh-token.repository.ts # Refresh token repository
│   ├── openapi.config.ts          # OpenAPI/Swagger configuration
│   └── index.ts                   # Main application
├── .env.example                   # Environment variables template
├── package.json
├── tsconfig.json
└── README.md
```

## OpenAPI Entegrasyonu

Bu örnek `@developersailor/express-openapi-decorators` paketini kullanır:

```typescript
import { Controller, Get, Route, Tags, Summary, Security } from '@developersailor/express-openapi-decorators';

@Controller('/api')
@Tags('Profile')
export class ProfileController {
  @Get('/profile')
  @Summary('Get user profile')
  @Security('bearerAuth')
  getProfile() {
    // ...
  }
}
```

## Güvenlik Notları

1. **JWT_SECRET** ve **REFRESH_TOKEN_SECRET** çok güçlü ve benzersiz olmalı:
   ```bash
   # Secret üretme
   node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
   ```

2. Production'da `.env` dosyasını asla commit etmeyin

3. HTTPS kullanın (secure cookie ayarı)

4. Rate limiting ekleyin:
   ```bash
   npm install express-rate-limit
   ```

5. CORS ayarlarını yapın:
   ```bash
   npm install cors
   ```

## Çevre Değişkenleri

```env
# Database
DATABASE_URL="file:./dev.db"

# JWT Secrets (generate strong random strings!)
JWT_SECRET="your-super-secret-jwt-key-min-32-chars-long-xxx"
REFRESH_TOKEN_SECRET="your-different-super-secret-refresh-key-yyy"

# Server
PORT=3000
NODE_ENV=development
```

## Lisans

MIT
