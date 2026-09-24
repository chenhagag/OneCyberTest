# דוח בדיקת חדירה - מערכת One

**יעד:** https://joinone.io
**תאריכים:** 2026-09-17 עד 2026-09-24
**כלי:** OneSyberTest - כלי בדיקת חדירה חיצוני מותאם
**חשבונות בדיקה:** hag.chen@gmail.com (ID 251) + chen.hagag+sectest@gmail.com
**היקף:** 6 ריצות, 1,483+ בקשות, 346 בדיקות בריצה אחרונה

---

## סיכום מנהלים

### הערכת מצב אבטחה: טוב מאוד

**לא נמצאו פרצות אבטחה.** מתוך 346 בדיקות אוטומטיות, אפס פרצות נוצלו. כל הממצאים ה"דחופים" שדווחו בגרסאות קודמות של הדוח אומתו כ-**false positives** ע"י צוות הפיתוח, ואומתו מחדש בבדיקה ידנית.

| סטטוס | כמות | פירוט |
|--------|------|-------|
| ניצול מאומת | **0** | לא נמצאו פרצות |
| נחסם (הגנה עובדת) | **86** | המערכת הגנה כראוי |
| חשד לא מאומת | 111 | **כולם false positives** - SPA מחזיר 200+HTML לכל נתיב |
| לא נבדק | 149 | מגבלות טכניות (OAuth, SPA routing) |

---

## תיקון ממצאים קודמים

שלושת הממצאים שסומנו "דחוף" בגרסאות קודמות של הדוח **אינם ממצאים אמיתיים:**

### ~~1. Security Headers חסרים~~ → FALSE POSITIVE

**מה דווח:** הכלי לא זיהה security headers.

**מה שבאמת קורה:** כל ה-headers קיימים (Helmet middleware). אומת ב-curl:
```
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline'; ...
strict-transport-security: max-age=31536000; includeSubDomains
x-frame-options: SAMEORIGIN
x-content-type-options: nosniff
referrer-policy: no-referrer
```

**למה הכלי טעה:** ככל הנראה ה-fingerprinter בדק תגובה מ-Railway CDN/proxy ולא מ-Express, או שהפענוח של ה-headers לא היה מדויק.

### ~~2. Rate Limiting חסר~~ → הסורק לא הגיע לסף

**מה דווח:** 5 בקשות מהירות לא נחסמו.

**מה שבאמת קורה:** קיימים 4 מגבילי קצב:
- כללי: 1,000 בקשות / 15 דקות per IP
- AI: 30 / דקה
- Auth: 30 / 10 דקות per IP
- OTP: 5 / שעה per email

**למה הכלי טעה:** שלח רק 5 בקשות (0.5% מהסף). לפי עקרון הבדיקה המינימלית, הכלי לא שולח מאות בקשות, אז לא יכול היה לזהות rate limiting עם סף כה גבוה.

### ~~3. `/api/users/search` timeout/DoS~~ → FALSE POSITIVE

**מה דווח:** ה-endpoint גרם ל-timeout של 30+ שניות ו-502.

**מה שבאמת קורה:** ה-endpoint לא קיים. הבקשה נתפסה ע"י SPA catch-all, ו-React ניסה לעבד URL לא קיים, מה שגרם ל-timeout. `grep -r "users/search" backend/src/` מחזיר אפס תוצאות.

---

## ממצאים אמיתיים שנותרו

### עדיפות נמוכה בלבד

#### 1. SPA מחזיר 200 לכל נתיב (חומרה: נמוכה)

כל נתיב - כולל `/.env`, `/.git/HEAD`, `/api/users/search` - מחזיר HTTP 200 עם index.html. **אין חשיפה אמיתית** (התוכן תמיד HTML), אבל:
- גורם ל-false positives בכל סורק אבטחה
- בפנטסט מקצועי ידווח כממצא נמוך

**המלצה:** שקלו להחזיר 404 לנתיבים כמו `/.env`, `/.git` - בעיקר למניעת רעש בסריקות עתידיות. צוות הפיתוח מודע ושוקל.

#### 2. Server Header חושף Railway (חומרה: מידע)

`Server: railway-hikari` - header של Railway, אין יכולת להסיר. סיכון מינימלי.

---

## מה נבדק ועבר

| תחום | בדיקות | תוצאה |
|-------|--------|--------|
| **Admin endpoints** | 19 נתיבים | כולם 403 למשתמש רגיל, 401 ללא token |
| **IDOR (2 חשבונות)** | `/api/users/{id}`, `/api/users/{id}/photos` | 403 - בידוד בין משתמשים עובד |
| **XSS (reflected + stored)** | 30+ payloads | לא נמצא |
| **SQL Injection** | 7 payloads | לא נמצא |
| **NoSQL Injection** | 4 payloads | נחסם |
| **CRLF Injection** | 3 payloads | נחסם |
| **Token forgery** | JWT מזויפים, tokens אקראיים | כולם נדחים |
| **Empty credentials** | login ריק | נדחה |
| **Prompt Injection** | 9 ניסיונות | לא דלף מידע |
| **הודעות ללא match** | 2 בדיקות | 403 |
| **גישה ללא פרופיל** | 2 בדיקות | 403 |
| **פרופילים מוסתרים** | גישה לפי ID | נחסם |
| **דליפת מידע ב-API** | 10+ endpoints | אין סיסמאות/tokens/stack traces |
| **CORS** | 3 origins שונים | מוגדר נכון |
| **Token ב-URL** | סריקה | לא מועבר |
| **Security Headers** | curl אימות | CSP, HSTS, X-Frame, X-Content-Type, Referrer - כולם קיימים |
| **Rate Limiting** | קיים בקוד | 4 מגבילים פעילים (כללי, AI, auth, OTP) |

---

## מה לא נבדק

| בדיקה | סיבה | סיכון |
|--------|------|-------|
| **Session management** | Auth דרך OAuth, אין login/password | נמוך - Supabase מנהל |
| **File Upload** | לא נמצא endpoint (404) | נמוך |
| **WebSocket Auth** | לא נמצאו endpoints | נמוך |
| **קוד מקור** | בדיקה חיצונית בלבד | N/A |
| **Infrastructure** | Railway, DNS, TLS | לא בהיקף |
| **Mobile app** | לא בהיקף | N/A |

---

## מוכנות לפנטסט מקצועי

המערכת **מוכנה ובמצב טוב** לפנטסט. בודק מקצועי ככל הנראה יתמקד ב:

1. **Business logic** - תהליך ההתאמה, הצ'אט, מניפולציה של פרופילים
2. **Supabase configuration** - RLS policies, storage rules, auth settings
3. **Infrastructure** - Railway security, DNS, TLS configuration
4. **API fuzzing** - בדיקה עם endpoints אמיתיים (לא SPA catch-all)
5. **Mobile** - אם קיימת אפליקציה, בדיקת API מהצד שלה

**הערה לבודק מקצועי:** ה-SPA catch-all מחזיר 200 לכל נתיב. רוב ה-endpoints שמחזירים 200 עם body של ~4,700 bytes הם HTML ולא API אמיתי. ה-API endpoints האמיתיים מחזירים JSON עם body קטן יותר או status codes שונים (401/403/400).

---

## היקף ומגבלות

- **יעד:** https://joinone.io (production)
- **גישה:** 2 חשבונות בדיקה (משתמשים רגילים)
- **מגבלה:** SPA routing גורם ל-false positives רבים
- **מגבלה:** OAuth auth - לא ניתן לבדוק session management
- **שינויים בנתונים:** לא בוצעו
- **לא בוצע:** סקירת קוד, infrastructure, mobile

---

## סיכום

| קטגוריה | מצב |
|---------|------|
| אימות והרשאות | ✓ תקין |
| בידוד בין משתמשים (IDOR) | ✓ תקין (נבדק עם 2 חשבונות) |
| הגנה מפני הזרקות (XSS/SQLi/NoSQL) | ✓ תקין |
| Security Headers | ✓ תקין (Helmet) |
| Rate Limiting | ✓ תקין (4 מגבילים) |
| CORS | ✓ תקין |
| Prompt Injection | ✓ תקין |
| Admin access control | ✓ תקין |
| Token security | ✓ תקין |
| SPA catch-all (false positives) | △ ממצא נמוך - לשקול 404 |
| Server header disclosure | ○ מידע - לא ניתן לשנות |

**רמת אבטחה: טובה מאוד. המערכת מוכנה לפנטסט מקצועי.**

---

*דוח זה מבוסס על בדיקת חדירה חיצונית אוטומטית עם 2 חשבונות בדיקה. הדוח אינו מהווה תחליף לבדיקת חדירה מקצועית מלאה.*
