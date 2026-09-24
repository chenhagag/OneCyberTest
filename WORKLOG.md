# WORKLOG - One Penetration Testing Tool

## 2026-09-17

### בניית הכלי
- נקראו הנחיות מפורטות מקובץ `Instructions.txt`
- תוכננה ארכיטקטורה מודולרית: core/, recon/, tests/
- נבנו 22 קבצי Python:
  - **core/** (6 קבצים): config, http_client, safety, logger, reporter, __init__
  - **recon/** (4 קבצים): crawler, tech_fingerprint, api_discovery, __init__
  - **tests/** (11 קבצים): unauth_access, auth_bypass, idor, admin_access, input_validation, info_disclosure, session_mgmt, prompt_injection, rate_limiting, matching_bypass, __init__
  - **run_pentest.py**: סקריפט ראשי
- נוצרו config.yaml ו-requirements.txt
- כל הקבצים עברו בדיקת syntax ו-import בהצלחה

### הרצה ראשונה (dry-run) - כשלון חלקי
- RealDataDetector זיהה false positive בקוד JS (מספרי טלפון לדוגמה)
- שגיאה: `SecurityHeaders has no len()` ב-fingerprinting
- תוצאה: 23 endpoints נמצאו (JS scan נעצר בגלל ה-safety stop)

### תיקון באגים
- תוקן RealDataDetector:
  - מדלג על תוכן JavaScript/CSS
  - מתעלם ממספרי טלפון לדוגמה
  - מסנן מספרי ת.ז. מתחת ל-100M
  - מעביר content_type לפונקציית scan
- תוקן len() על SecurityHeaders - סופר שדות שאינם None

### הרצה שנייה (dry-run) - הצלחה
- 35 בקשות, 19 שניות
- **161 API endpoints** נמצאו מתוך ניתוח JS
- ממצאי סיור:
  - Server: railway-hikari (חושף hosting)
  - חסרים security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
  - /api/users מחזיר 401 (מוגן - חיובי)
  - /api/login ו-/api/register קיימים (400 ללא פרמטרים)
  - /api/health פתוח (11 bytes)
  - /api/auth עושה redirect (כנראה OAuth)
  - SPA - כל הנתיבים מחזירים אותו HTML
  - אין cookies ללא auth - כנראה token-based (Supabase)
- נוצר דוח ממצאים: `reports/conclusions_unauthenticated.md`

## 2026-09-23

### תיקון באגים ב-test modules
- נמצאו 3 באגים מערכתיים בכל 10 מודולי הבדיקה:
  1. `authenticated=True/False` - פרמטר שלא קיים ב-SecureHTTPClient (הוסר)
  2. `recommendation=` -> `remediation=` - שם שדה שגוי ב-TestResult (תוקן)
  3. `ep.lower()` - endpoints הם dicts לא strings, צריך `ep["url"]` (תוקן)
- הוסף תמיכה ב-`--token` flag ו-`ONE_ACCESS_TOKEN` env var ל-run_pentest.py

### הרצה ראשונה עם token - כשלון
- Token התקבל מ-Chen (hag.chen@gmail.com, user ID: 251)
- Token עבד: /api/users החזיר 403 (לא 401) = אימות תקין
- כל 10 מודולי הבדיקה קרסו בגלל 3 הבאגים הנ"ל
- 0 תוצאות נרשמו

### תיקון באגים - batch fix
- 2 סוכנים תיקנו את כל 10 הקבצים במקביל
- הוסרו כל ה-`authenticated=` (23 מקומות)
- שונו כל ה-`recommendation=` ל-`remediation=` (61 מקומות)
- תוקנו כל ה-`ep.lower()` ל-`ep["url"].lower()` (12 מקומות)

### הרצה שנייה עם token - הצלחה
- 172 בקשות, 377 שניות (~6 דקות)
- **58 בדיקות** הושלמו:
  - 0 ניצול הצליח ואומת
  - 18 חשד שלא אומת
  - 31 נחסם (המערכת הגנה)
  - 9 לא נבדק

#### ממצאים עיקריים:
- **Security Headers חסרים** (CSP, HSTS, X-Frame-Options) - כולם חסרים
- **Rate Limiting חסר** - login ו-API לא מגבילים בקשות מהירות
- **SPA מחזיר 200 לכל נתיב** - כולל .env, .git - false positives
- **Onboarding/Subscription bypass** - חשד שלא אומת (ייתכן SPA HTML)
- **Server header** חושף railway-hikari

#### ממצאים חיוביים:
- API endpoints מוגנים (401/403 ללא auth)
- CORS מוגדר נכון (אין wildcard)
- Prompt injection - 9 ניסיונות נחסמו
- אין דליפת מידע רגיש ב-API responses
- הודעות ללא match נחסמות
- גישה לפרופילים לפי ID נחסמת

#### מה לא רץ:
- unauth_access, auth_bypass, admin_access, input_validation (XSS/SQLi) - קרסו בהרצה הראשונה, תוקנו אך לא רצו שוב
- Session management - דורש login עם credentials (לא OAuth)
- IDOR בין משתמשים - דורש חשבון שני

### דוחות
- `reports/conclusions_full_report.md` - דוח מסקנות מלא בעברית
- `reports/pentest_20260923_113547.json` - פלט מובנה
- `reports/pentest_20260923_113547.html` - דוח HTML

### סטטוס
- [x] בניית כלי הבדיקה
- [x] סיור חיצוני ללא התחברות
- [x] דוח ממצאים - סיור
- [x] הגדרת חשבון בדיקה (token מ-Chen)
- [x] הרצה מלאה עם התחברות (חלקית - 6/10 מודולים)
- [x] דוח ממצאים - בדיקה מלאה
### הרצה שלישית - 4 מודולים חסרים
- תוקן TestResult: שדות test_module, target_url, expected_behavior, actual_behavior הפכו ל-optional
- רצו: unauth_access, auth_bypass, admin_access, input_validation
- 254 בדיקות, 339 בקשות, ~2 שעות (timeout בגלל /api/users/search)
- תוצאות:
  - 0 ניצול מאומת
  - 65 חשד (רובם SPA false positives - 200 לכל נתיב)
  - 51 נחסמו (admin 403, XSS/SQLi/NoSQL/CRLF blocked, token forgery rejected)
  - 138 לא נבדקו (circuit breaker מ-timeouts ב-/api/users/search)

#### ממצאים חדשים (ריצה 3):
- **/api/users/search גורם ל-timeout/502** על קלט XSS - סיכון DoS (חומרה: בינונית)
- **Admin endpoints מוגנים** - 19 נתיבים, כולם 403 (חיובי)
- **Token forgery נחסם** (חיובי)
- **XSS/SQLi/NoSQL/CRLF לא נמצאו** - 5 קטגוריות injection, כולן blocked (חיובי)
- **Empty credentials נדחים** (חיובי)

### שיפורי כלי
- Per-URL timeout tracking - endpoint שנתקע לא מפיל circuit breaker גלובלי
- RuntimeGuard.reset() - 60 דקות מתחילות מהבדיקות, לא מה-recon
- Input validation מדלג על endpoint שעושה timeout

### הרצה רביעית - מלאה עם כל השיפורים
- 344 בדיקות, 486 בקשות, **403 שניות** (~6.7 דקות, במקום 2 שעות!)
- תוצאות: 0 exploited, 111 suspected, 83 blocked, 150 not_tested
- **111 suspected** - רובם SPA false positives (HTTP 200 + index.html)
- **83 blocked** - admin(19), unauth(24), info_disc(16), input_val(5), auth_bypass(2), idor(4), prompt_inj(9), session(1), matching(3)
- IDOR: `/api/users/{id}` מחזיר 403 (מוגן), `/api/profile/{id}` מחזיר SPA HTML (false positive)
- `/api/users/search` - timeout מזוהה ומדולג (per-URL tracking עובד!)

### סטטוס מעודכן
- [x] בניית כלי הבדיקה
- [x] סיור חיצוני ללא התחברות
- [x] דוח ממצאים - סיור
- [x] הגדרת חשבון בדיקה
- [x] הרצה מלאה - כל 10 המודולים
- [x] דוח ממצאים מלא (reports/conclusions_full_report.md)
### הרצה חמישית - regression test אחרי תיקוני Chen
- 346 בדיקות, 486 בקשות, 412 שניות
- תוצאות: 0 exploited, 111 suspected, **86 blocked (+3)**, 149 not_tested
- **+3 blocked** לעומת לפני התיקונים - שיפור, אין רגרסיה
- דוח מלא עודכן: reports/conclusions_full_report.md

## 2026-09-24

### הרצה שישית - חשבון בדיקה שני (IDOR)
- חשבון: chen.hagag+sectest@gmail.com (UUID: 97adbc4e-272c-4f31-b4e5-3b3f6ad1cccc)
- 344 בדיקות, 486 בקשות, 342 שניות
- תוצאות: 0 exploited, 111 suspected, 85 blocked, 148 not_tested
- IDOR: `/api/users/{id}` -> 403, `/api/users/{id}/photos` -> 403 (מוגן!)
- כל שאר ה-200 הם SPA HTML false positives
- תוצאות זהות לשני החשבונות - המערכת עקבית

### סטטוס סופי
- [x] בניית כלי הבדיקה
- [x] סיור חיצוני
- [x] הרצה מלאה (כל 10 מודולים)
- [x] regression test אחרי תיקונים (+3 blocked, אין רגרסיה)
- [x] דוח ממצאים מלא
- [x] בדיקת IDOR עם חשבון שני - מוגן (403)
- [x] אימות security headers - FALSE POSITIVE, כולם קיימים (Helmet middleware)
- [x] אימות rate limiting - קיים (4 מגבילים), הסורק לא הגיע לסף
- [x] אימות /api/users/search - FALSE POSITIVE, endpoint לא קיים (SPA catch-all)
- [x] דוח סופי מעודכן עם התייחסות צוות הפיתוח

### הערות
- Token של Supabase פג תוקף אחרי שעה - צריך חדש לכל הרצה
- חשבון הבדיקה הוא hag.chen@gmail.com (לא האדמין chen.hagag@gmail.com)
- עדיף חשבון שני רגיל (לא אדמין) לבדיקת IDOR
