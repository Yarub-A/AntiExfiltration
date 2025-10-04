# AntiExfiltration

حل شامل لحماية أنظمة ويندوز من تسريب البيانات، يعتمد على اعتراض الشبكات، تحليل الذاكرة، وتتبع العمليات في الزمن الحقيقي. يشمل المشروع خدمة تعمل بامتيازات مرتفعة، وكونسول مراقبة غني.

## بنية المشروع

```
AntiExfiltrationSystem.sln
└── src/AntiExfiltrationSystem
    ├── Program.cs
    ├── Core/            # محرك الكشف والتنسيق
    ├── Detection/       # تحليل الحمولة ورد الفعل
    ├── Infrastructure/  # كونسول العرض
    ├── Memory/          # تحليل الذاكرة والهيب
    ├── Networking/      # التقاط الحزم وإدارة البروكسي العكسي
    ├── ProcessMonitoring/# تتبع العمليات والسياق
    ├── ReverseProxy/    # اعتراض TLS في الزمن الحقيقي
    ├── ThreatIntel/     # (مكان لتوسعة استخبارات التهديد)
    └── Utilities/       # أدوات مشتركة
```

## متطلبات النظام

- Windows 10/11 x64
- صلاحيات Administrator/SYSTEM
- .NET SDK 8.0 أو 9.0 (مع دعم Windows)
- منفذ حر للبروكسي العكسي (الافتراضي 8443)

## الإعداد والتشغيل

1. **استعادة الحزم**
   ```powershell
   dotnet restore AntiExfiltrationSystem.sln
   ```
2. **البناء**
   ```powershell
   dotnet build AntiExfiltrationSystem.sln -c Release -f net8.0-windows
   ```
3. **البناء لإطار .NET 9 (اختياري عند توافر SDK 9)**
   ```powershell
   dotnet build AntiExfiltrationSystem.sln -c Release -f net9.0-windows
   ```
4. **النشر الذاتي (اختياري)**
   ```powershell
   dotnet publish src/AntiExfiltrationSystem/AntiExfiltrationSystem.csproj -c Release -r win-x64 -f net8.0-windows --self-contained true
   ```
5. **التشغيل بامتيازات مرتفعة**
   ```powershell
   Start-Process (Resolve-Path "./src/AntiExfiltrationSystem/bin/x64/Release/net8.0-windows/AntiExfiltrationSystem.exe") -Verb RunAs
   ```
   > إذا تم البناء لإطار .NET 9، استخدم المسار `net9.0-windows` بنفس الصيغة.

## المزايا الرئيسية

- اعتراض حقيقي لحزم الشبكة عبر مقابس RAW
- بروكسي عكسي مع كسر TLS وإنشاء شهادات ديناميكية
- تتبع عمليات فوري باستخدام WMI
- تحليل ذاكرة متقدم مع استخراج سلاسل حساسة واكتشاف Hooks
- تنسيق ردود تلقائي (تسجيل، تشويش، حجب، قتل العملية)
- واجهة كونسول لحظية تعرض إحصاءات وتنبيهات

## الأمان وأفضل الممارسات

- يتم إنشاء سلطة جذر خاصة وتخزينها في مخزن الشهادات المحلي بأمان
- جميع الاتصالات المريبة تؤدي إلى إعادة ضبط TCP أو إنهاء العملية حسب مستوى الخطر
- يتم مسح البيانات الحساسة من الذاكرة العاملة أثناء المعالجة
- يعتمد المشروع على تسجيل كامل للعمليات لضمان إمكانية التدقيق لاحقًا

## الاختبارات

- ينصح بتشغيل النظام في بيئة اختبار مع حركة مرور حقيقية للتحقق من الاعتراض
- يمكن اختبار اكتشاف السلاسل الحساسة بحقن نصوص تضم كلمات مرور أو مفاتيح API داخل عمليات خبيثة
- يوصى بإنشاء سيناريوهات تسريب (مثل رفع ملف بصيغة JSON يحتوي بيانات سرية) للتأكد من استجابة النظام

> **ملاحظة:** يجب تثبيت التطبيق على جهاز ويندوز فعلي أو VM. البيئة الحالية (Linux) مخصصة لتحرير الكود فقط.
