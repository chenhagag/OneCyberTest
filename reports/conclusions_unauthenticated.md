# דוח ממצאים - סיור חיצוני ללא התחברות (Unauthenticated Reconnaissance)

**יעד:** https://joinone.io
**תאריך:** 2026-09-17
**סוג בדיקה:** סיור חיצוני בלבד (dry run), ללא ניסיונות ניצול
**משך:** ~19 שניות
**בקשות שנשלחו:** 35

---

## סיכום מנהלים

הסיור החיצוני חשף מידע משמעותי על ארכיטקטורת המערכת. נמצאו **161 API endpoints** מתוך ניתוח קוד ה-JavaScript, חלקם מוגנים (מחזירים 401) וחלקם פתוחים. נמצאו מספר חולשות בינוניות ונמוכות הנוגעות ל-headers אבטחה חסרים וחשיפת מידע.

---

## ממצאים

### 1. חוסר ב-Security Headers (חומרה: בינונית)

**מצב נוכחי:** רק header אחד קיים (`Server: railway-hikari`).

**חסרים:**
| Header | תפקיד | סיכון |
|--------|--------|-------|
| `X-Frame-Options` | מניעת Clickjacking | תוקף יכול להטמיע את האתר ב-iframe ולגנוב קליקים |
| `Content-Security-Policy` | מניעת XSS והזרקות | אין הגנה מפני סקריפטים זדוניים |
| `Strict-Transport-Security` (HSTS) | אכיפת HTTPS | אפשר לבצע downgrade ל-HTTP |
| `X-Content-Type-Options` | מניעת MIME sniffing | הדפדפן עלול לפרש תוכן באופן שגוי |
| `X-XSS-Protection` | הגנת XSS בדפדפן | חסרה שכבת הגנה נוספת |
| `Referrer-Policy` | שליטה בחשיפת referrer | URL-ים פנימיים עלולים לדלוף לאתרים חיצוניים |
| `Permissions-Policy` | הגבלת APIs של הדפדפן | לא מוגבלת גישה למצלמה, מיקום וכו' |

**המלצה:** הוסיפי את כל ה-headers החסרים בהגדרות השרת או ב-middleware.

---

### 2. חשיפת זהות השרת (חומרה: נמוכה)

**ממצא:** ה-header `Server: railway-hikari` חושף שהאפליקציה רצה על Railway.

**סיכון:** מאפשר לתוקף לכוון את ההתקפה לפגיעויות ספציפיות של Railway.

**המלצה:** אם אפשר, הסירי או שני את ה-Server header.

---

### 3. SPA ללא הגנת routing בצד שרת (חומרה: מידע)

**ממצא:** כל הנתיבים (כולל `/robots.txt`, `/sitemap.xml`, `/.env`, `/.well-known/*`) מחזירים את אותו תוכן HTML (4,586 bytes) עם קוד סטטוס 200.

**משמעות:**
- זו אפליקציית SPA (Single Page Application) שה-routing שלה בצד הלקוח
- הקובץ `/.env` מחזיר 200 אבל מכיל את ה-HTML של האפליקציה, לא קובץ env אמיתי - **אין חשיפת סודות**
- אותו דבר לגבי `/robots.txt`, `/sitemap.xml` - הם לא קבצים אמיתיים
- `/manifest.json` הוא קובץ אמיתי (534 bytes, תוכן שונה)
- `/api/health` הוא endpoint אמיתי (11 bytes)

**סיכון:** בינתיים אין סיכון ממשי, אבל זה מקשה על הבחנה בין endpoints אמיתיים לבין routes של ה-SPA.

---

### 4. API Endpoints שנחשפו (חומרה: מידע)

**161 endpoints נמצאו** מתוך ניתוח קוד ה-JavaScript (`index-DnsPNYNU.js`, 873KB).

**endpoints בולטים שנבדקו:**

| Endpoint | תגובה | הערה |
|----------|--------|------|
| `GET /api/health` | 200 (11 bytes) | פתוח - תקין |
| `GET /api/users` | **401** (39 bytes) | מוגן - דורש אימות |
| `POST /api/login` | 400 (29 bytes) | קיים, דורש פרמטרים |
| `POST /api/register` | 400 (45 bytes) | קיים, דורש פרמטרים |
| `GET /api/auth` | Redirect | מפנה (כנראה ל-OAuth) |

**הערה חיובית:** `/api/users` מחזיר 401 ולא 200 - סימן שיש אימות תקין ברמת ה-API.

---

### 5. Cookies (חומרה: מידע)

**ממצא:** לא נמצאו cookies בתגובה לבקשות ללא התחברות.

**משמעות:** המערכת כנראה משתמשת ב-token-based auth (JWT/Bearer) ולא ב-session cookies. יש לבדוק זאת בשלב ה-authenticated.

---

### 6. קוד JavaScript חשוף (חומרה: מידע)

**ממצא:** קובץ JavaScript יחיד (873KB) מכיל את כל הלוגיקה של ה-frontend, כולל:
- כל נתיבי ה-API (161 endpoints)
- מבנה הבקשות (שדות, פרמטרים)
- לוגיקת routing ותהליכי עבודה

**משמעות:** זה רגיל ב-SPA, אבל מספק לתוקף מפה מלאה של ה-API. בשלב הבא ננתח את ה-endpoints שנחשפו ונבדוק אותם בפועל.

---

## מה לא נבדק (יבדק בשלב הבא)

- [ ] גישה ל-API endpoints עם ובלי אימות
- [ ] IDOR - גישה למידע של משתמש אחר
- [ ] גישה לפעולות אדמין
- [ ] XSS, SQL injection, input validation
- [ ] ניהול session ו-token
- [ ] Prompt injection בצ'אט
- [ ] Rate limiting
- [ ] עקיפת תהליך היכרות/התאמה
- [ ] CORS configuration בפועל (בבקשות cross-origin)

---

## תעדוף תיקונים

1. **עדיפות גבוהה:** הוספת Security Headers (CSP, HSTS, X-Frame-Options) - פשוט ליישום, משפר משמעותית
2. **עדיפות בינונית:** הסרת/שינוי Server header
3. **עדיפות נמוכה:** בדיקה שה-SPA לא חושף routes שלא צריך

---

*דוח זה מבוסס על סיור חיצוני בלבד. הבדיקות המלאות (עם התחברות) יכסו את תחומי הבדיקה שלא נבדקו.*
