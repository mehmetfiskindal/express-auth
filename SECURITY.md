# Güvenlik Rehberi

Bu rehber, `@developersailor/express-auth` paketinin güvenlik özelliklerini ve en iyi uygulamaları açıklar.

## 📋 Güvenlik Kontrol Listesi

- [x] Güçlü JWT Secret (min 32 karakter, rastgele)
- [x] HTTPS (güvenli çerezler)
- [x] Rate Limiting
- [x] CORS Yapılandırması
- [x] Ortam Değişkenleri (secrets için)
- [x] Şifre Validasyon Kuralları
- [x] Token Süre Ayarları
- [x] Refresh Token Temizlik Job
- [x] Şüpheli Aktivite Monitörü

---

## 🔐 1. Güçlü JWT Secret

### Gereksinimler
- Minimum 32 karakter uzunluğunda
- Rastgele üretilmiş
- Tahmin edilemez (sözlük kelimeleri içermez)

### Üretim
```bash
# Node.js ile 64 karakterlik güçlü secret üretin
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Kullanım
```env
# .env
JWT_SECRET="ac4abd93c4e7fc43d9424af0543c51714d2a45070c82d3bb5aa12c8e3ab98e5a"
REFRESH_TOKEN_SECRET="farkli_bir_secret_cok_guclu_olmalidir_012345678901234567890123456789"
```

Paket otomatik olarak secret güçlülüğünü kontrol eder:
- 32 karakterden kısa secret'ları reddeder
- `password`, `secret`, `123456`, `admin`, `test`, `default` içeren secret'ları reddeder

---

## 🔒 2. HTTPS (Güvenli Çerezler)

### Üretim Ortamında
```typescript
const authConfig = {
  cookie: {
    httpOnly: true,
    secure: true, // HTTPS only!
    sameSite: 'strict',
  },
};
```

### HTTPS Enforcement Middleware
```typescript
import { createSecurityMiddleware } from '@developersailor/express-auth';

const security = createSecurityMiddleware({
  https: {
    enabled: true,
    hstsMaxAge: 31536000, // 1 yıl
    hstsIncludeSubdomains: true,
    hstsPreload: true,
  },
});

// Uygula
security.apply(app);
```

Bu middleware:
- HTTP trafiğini HTTPS'e yönlendirir
- HSTS başlıkları ekler
- Güvenlik başlıklarını (CSP, X-Frame-Options vb.) ayarlar

---

## ⚡ 3. Rate Limiting

### Yapılandırma
```typescript
const authConfig = {
  rateLimit: {
    enabled: true,
    general: {
      windowMs: 15 * 60 * 1000, // 15 dakika
      maxRequests: 100,
    },
    auth: {
      windowMs: 15 * 60 * 1000,
      maxRequests: 5, // Auth endpointleri için daha katı
    },
    strict: {
      windowMs: 60 * 60 * 1000, // 1 saat
      maxRequests: 10, // Çok katı
    },
  },
};
```

### Bağımsız Kullanım
```typescript
import { createRateLimitMiddleware } from '@developersailor/express-auth';

const rateLimiter = createRateLimitMiddleware(15 * 60 * 1000, 100);
app.use('/api/', rateLimiter);
```

### Yanıt Başlıkları
Rate limiting etkinleştirildiğinde şu başlıklar eklenir:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

Limit aşıldığında:
```
HTTP/1.1 429 Too Many Requests
Retry-After: 900
```

---

## 🌐 4. CORS Yapılandırması

### Üretim Ortamında
```typescript
const authConfig = {
  cors: {
    origin: [
      'https://yourdomain.com',
      'https://app.yourdomain.com',
    ],
    credentials: true, // Cookie gönderimi için gerekli
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
    ],
  },
};
```

### Geliştirme Ortamında
```typescript
const authConfig = {
  cors: {
    origin: '*', // Geliştirme için serbest
    credentials: true,
  },
};
```

### Wildcard Subdomain Desteği
```typescript
cors: {
  origin: ['*.yourdomain.com'], // Alt domainler için
}
```

---

## 📝 5. Ortam Değişkenleri

### Örnek .env Dosyası
```env
# Database
DATABASE_URL="postgresql://user:pass@localhost:5432/dbname"

# JWT Secrets (güçlü ve rastgele)
JWT_SECRET="64karakterlik_guclu_random_hex_string..."
REFRESH_TOKEN_SECRET="farkli_64karakterlik_random_string..."

# CORS
ALLOWED_ORIGINS="https://yourdomain.com,https://app.yourdomain.com"

# Server
NODE_ENV=production
PORT=3000

# Rate Limiting (opsiyonel)
MAX_FAILED_ATTEMPTS=5
BLOCK_DURATION_MINUTES=30
```

### Güvenlik İpuçları
1. `.env` dosyasını asla Git'e commit etmeyin
2. `.env.example` dosyası kullanın
3. Üretim secret'larını farklı tutun
4. Düzenli olarak secret'ları değiştirin

---

## 🔑 6. Şifre Validasyon Kuralları

### Varsayılan Kurallar
```typescript
const authConfig = {
  passwordRules: {
    minLength: 8,           // Minimum 8 karakter
    requireUppercase: true,  // En az bir büyük harf
    requireLowercase: true,  // En az bir küçük harf
    requireNumbers: true,    // En az bir rakam
    requireSpecialChars: true, // En az bir özel karakter
  },
};
```

### Özel Kurallar
```typescript
passwordRules: {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: false, // Özel karakter zorunlu değil
}
```

### Programatik Validasyon
```typescript
import { PasswordService } from '@developersailor/express-auth';

const passwordService = new PasswordService();
const validation = passwordService.validatePasswordStrength(password, {
  minLength: 10,
  requireUppercase: true,
});

if (!validation.valid) {
  console.log(validation.errors);
  // ['Password must be at least 10 characters long', ...]
}
```

---

## ⏰ 7. Token Süre Ayarları

### Önerilen Süreler
```typescript
const authConfig = {
  // Access Token: Kısa süreli (15 dakika)
  accessTokenExpiresIn: '15m',
  
  // Refresh Token: Daha uzun (7 gün)
  refreshTokenExpiresIn: '7d',
};
```

### Süre Formatları
```typescript
// String formatları
accessTokenExpiresIn: '15m'  // 15 dakika
accessTokenExpiresIn: '1h'   // 1 saat
accessTokenExpiresIn: '7d'   // 7 gün

// Sayı formatı (saniye)
accessTokenExpiresIn: 900    // 15 dakika
```

---

## 🧹 8. Refresh Token Cleanup Job

### Otomatik Temizlik
```typescript
const authConfig = {
  tokenCleanup: {
    enabled: true,
    interval: 60 * 60 * 1000,         // Her saat çalışır
    deleteAfterExpired: 24 * 60 * 60 * 1000, // 24 saat sonra sil
    cleanupRevoked: true,             // İptal edilenleri de temizle
  },
};
```

### Repository Implementasyonu
```typescript
// Prisma örneği
async cleanupExpiredTokens(): Promise<void> {
  await this.prisma.refreshToken.deleteMany({
    where: {
      expiresAt: { lt: new Date() },
    },
  });
}
```

### Manuel Temizlik
```typescript
// Auth router'dan erişim
const authRouter = createAuthRouter(authConfig);
await authRouter.tokenCleanupJob?.runCleanup();
```

---

## 👁️ 9. Şüpheli Aktivite Monitörü

### Yapılandırma
```typescript
const authConfig = {
  securityMonitor: {
    enabled: true,
    maxFailedAttempts: 5,              // 5 başarısız denemeden sonra engelle
    failedAttemptsWindow: 15 * 60 * 1000, // 15 dakika pencere
    blockDuration: 30 * 60 * 1000,     // 30 dakika engel
    trackConcurrentLogins: true,       // Aynı anda girişleri izle
    maxConcurrentSessions: 5,          // Maksimum 5 oturum
    alertThreshold: 70,                // Risk skoru 70+ bildirim gönder
  },
};
```

### Güvenlik Olayları
```typescript
import { SecurityMonitor } from '@developersailor/express-auth';

const securityMonitor = new SecurityMonitor(config);

// Olayları dinle
securityMonitor.on('securityEvent', (event) => {
  console.log('Güvenlik olayı:', event);
  
  if (event.type === 'brute_force_attempt') {
    // Bildirim gönder (Slack, Email vb.)
    sendAlert(`Brute force detected from ${event.ip}`);
  }
});
```

### Olay Tipleri
- `failed_login` - Başarısız giriş denemesi
- `brute_force_attempt` - Brute force saldırısı tespiti
- `suspicious_activity` - Şüpheli aktivite
- `token_reuse` - Token yeniden kullanımı (replay attack)
- `rate_limit_exceeded` - Rate limit aşımı
- `ip_blocked` - IP engellendi
- `concurrent_login` - Çoklu oturum uyarısı

### Güvenlik İstatistikleri
```typescript
// API endpoint (admin only)
app.get('/auth/security/stats', adminAuth, (req, res) => {
  const stats = security.getStats();
  res.json({
    blockedIPs: stats.security.blockedIPs,
    failedAttempts: stats.security.failedAttempts,
    activeSessions: stats.security.activeSessions,
    rateLimiterSizes: stats.rateLimiterSizes,
  });
});
```

---

## 🚀 Tam Güvenlik Yapılandırması

```typescript
import express from 'express';
import {
  createAuthRouter,
  createSecurityMiddleware,
} from '@developersailor/express-auth';

const app = express();

const authConfig = {
  // Secrets (ORTAM DEĞİŞKENLERİNDEN!)
  jwtSecret: process.env.JWT_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  
  // Token süreleri
  accessTokenExpiresIn: '15m',
  refreshTokenExpiresIn: '7d',
  
  // Repository'ler
  repositories: { userRepository, refreshTokenRepository },
  
  // Cookie ayarları
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  },
  
  // Şifre kuralları
  passwordRules: {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
  },
  
  // Rate limiting
  rateLimit: {
    enabled: true,
    general: { windowMs: 15 * 60 * 1000, maxRequests: 100 },
    auth: { windowMs: 15 * 60 * 1000, maxRequests: 5 },
  },
  
  // CORS
  cors: {
    origin: process.env.NODE_ENV === 'production'
      ? process.env.ALLOWED_ORIGINS?.split(',')
      : ['http://localhost:3000'],
    credentials: true,
  },
  
  // HTTPS
  https: {
    enabled: process.env.NODE_ENV === 'production',
  },
  
  // Güvenlik monitörü
  securityMonitor: {
    enabled: true,
    maxFailedAttempts: 5,
    failedAttemptsWindow: 15 * 60 * 1000,
    blockDuration: 30 * 60 * 1000,
  },
  
  // Token cleanup
  tokenCleanup: {
    enabled: true,
    interval: 60 * 60 * 1000,
  },
};

// Güvenlik middleware'ini uygula
const security = createSecurityMiddleware(authConfig);
security.apply(app);

// Auth router'ı ekle
app.use('/auth', createAuthRouter(authConfig));

// Güvenlik olaylarını dinle
security.getSecurityMonitor()?.on('securityEvent', (event) => {
  if (event.riskScore >= 70) {
    console.warn('⚠️  Yüksek riskli güvenlik olayı:', event);
    // Bildirim sisteminize entegre edin
  }
});
```

---

## 📊 Güvenlik Başlıkları

Paket otomatik olarak şu güvenlik başlıklarını ekler:

| Başlık | Değer | Açıklama |
|--------|-------|----------|
| `X-Content-Type-Options` | `nosniff` | MIME sniffing'i engeller |
| `X-Frame-Options` | `DENY` | Clickjacking koruması |
| `X-XSS-Protection` | `1; mode=block` | XSS koruması |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | HTTPS zorlama |
| `Content-Security-Policy` | CSP kuralları | XSS ve injection koruması |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Referrer kontrolü |
| `Permissions-Policy` | Çeşitli kısıtlamalar | API kısıtlamaları |

---

## 🔍 Güvenlik Testleri

### 1. Rate Limit Testi
```bash
# Çok fazla istek gönderin
for i in {1..10}; do
  curl -X POST http://localhost:3000/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}'
done
# 429 Too Many Requests almalısınız
```

### 2. Brute Force Testi
```bash
# 5 başarısız denemeden sonra engellenmeli
for i in {1..6}; do
  curl -X POST http://localhost:3000/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}'
done
# 6. istek 403 Forbidden döndürmeli
```

### 3. CORS Testi
```bash
# İzin verilmeyen origin'den istek
curl -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -X OPTIONS \
  http://localhost:3000/auth/login
# CORS hatası almalısınız
```

### 4. Cookie Güvenliği Testi
```bash
# Cookie'leri kontrol edin
curl -c cookies.txt -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"password"}'

# HttpOnly ve Secure flag'lerini kontrol edin
cat cookies.txt
```

---

## 🚨 Güvenlik Uyarıları

1. **Asla hard-coded secret kullanmayın** - Her zaman ortam değişkenleri kullanın
2. **Loglara hassas bilgi yazmayın** - Şifre, token vb. bilgileri loglamayın
3. **Geliştirme ve üretim secret'larını ayırın** - Farklı değerler kullanın
4. **Düzenli olarak secret'ları değiştirin** - Özellikle şüpheli durumlarda
5. **Bağımlılıkları güncel tutun** - `npm audit` kullanın
6. **HTTPS kullanın** - Üretimde kesinlikle gerekli
7. **Rate limiting kullanın** - DoS saldırılarına karşı koruyun
8. **Güvenlik başlıklarını yapılandırın** - Ekstra koruma katmanları

---

## 📚 Daha Fazla Bilgi

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP JWT Security](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Express.js Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
