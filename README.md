# Anti-Exfiltration Blueprint

هذا المستودع يحتوي على نقطة انطلاق عملية لبناء نظام مكافحة تسريب البيانات (Anti-Infostealer / Anti-Exfiltration) باستخدام C#.

## 📂 بنية المشروع
- `AntiExfiltration.sln`: ملف الحل الذي يجمع المشاريع.
- `src/AntiExfiltration.Core`: مكتبة أساسية تحتوي الوحدات (Capture, Context, Policy, Decision, Action, Intel, Logging, Pipeline).
- `src/AntiExfiltration.App`: تطبيق Console يوضح كيفية ربط الوحدات معًا ويقدّم وضعي تشغيل (تجريبي وحي).
- `docs/ARCHITECTURE.md`: شرح معماري مفصل وخارطة عمل ومراحل تطوير مقترحة.

## 🚀 التعليمات السريعة
1. تأكد من تثبيت .NET 8 SDK بالإضافة إلى متطلبات SharpPcap (WinPcap / npcap على ويندوز، libpcap على لينكس).
2. استعادة الحزم وبناء الحل:
   ```bash
   dotnet restore
   dotnet build
   ```
3. تشغيل التطبيق التجريبي (الوضع الافتراضي demo ينتج حزمًا تمثيلية):
   ```bash
   dotnet run --project src/AntiExfiltration.App
   ```
4. تشغيل التطبيق بوضع الالتقاط الحي مع تحديد الواجهة ومرشح BPF اختياريًا:
   ```bash
   dotnet run --project src/AntiExfiltration.App --mode live --device "Ethernet" --filter "tcp port 443"
   ```
5. تشغيل الاختبارات:
   ```bash
   dotnet test
   ```

> **ملاحظة:** البيئة الافتراضية هنا لا تحتوي على `dotnet`؛ ستحتاج لتثبيته محليًا لتشغيل الأوامر أعلاه.

## ⚙️ خيارات سطر الأوامر للتطبيق
| الخيار | الوصف |
|--------|-------|
| `--mode [demo|live]` | اختيار نمط التشغيل، الافتراضي `demo` يولد سيناريوهات تدريبية. |
| `--device <name>` | واجهة الشبكة في وضع `live`، يدعم مطابقة الاسم أو الوصف. |
| `--filter <bpf>` | مرشح BPF لتقليص الحزم الملتقطة (مثل `tcp port 443`). |
| `--interval <seconds>` | الفترة الزمنية بين الحزم في الوضع التدريبي. |
| `--allow-kill` | يسمح بإنهاء العملية المخالفة فعليًا (يتطلب صلاحيات عالية، استخدمه بحذر). |
| `--help` | عرض المساعدة المختصرة. |

## 🧱 الوحدات الرئيسية
| الوحدة | الهدف | ملفات رئيسية |
|--------|-------|--------------|
| Capture | اعتراض الحزم الصادرة وربطها بمعرف العملية. | `RawPacket`, `ICaptureProvider`, `PcapCaptureProvider`, `DemoCaptureProvider` |
| Context | جمع سياق العملية (اسم، توقيع، أصل). | `ProcessInfo`, `IProcessContextResolver`, `SystemProcessContextResolver`, `DemoProcessContextResolver` |
| Policy | تحليل المحتوى والسياق عبر عدة محللات وإرجاع أدلة موحدة. | `PolicyEngine`, `SignatureAnalyzer`, `EntropyAnalyzer`, `AnalyzerFinding` |
| Decision | تحويل نتيجة التحليل إلى قرار تنفيذي. | `DecisionEngine`, `DecisionEngineOptions` |
| Action | تنفيذ القرار (منع، تشويش، قتل عملية). | `ActionExecutor`, `ConsolePacketDropper`, `PayloadDataObfuscator`, `SafeProcessTerminator` |
| Intel | دمج مؤشرات التهديد الخارجية. | `IThreatIntelProvider`, `ThreatIntelManager` |
| Logging | تسجيل الأحداث بشكل منظم. | `IEventLogger`, `JsonEventLogger`, `ConsoleEventLogger`, `CompositeEventLogger` |
| Pipeline | الربط بين جميع المكونات. | `AntiExfiltrationPipeline` |

## 🧪 الاختبارات
- مشروع `AntiExfiltration.Tests` يحتوي على اختبارات وحدات لـ `EntropyAnalyzer` + `PolicyEngine` لضمان سلوك المحللات والتجميع.
- أضف اختبارات تكامل لاحقًا للتأكد من صحة تدفق القرارات عبر `AntiExfiltrationPipeline`.

## ✅ خارطة الطريق (Milestones)
1. **Learning Mode:** تفعيل الاعتراض والتسجيل فقط لمراقبة السلوك.
2. **Policy Enforcement:** تفعيل محرك السياسات والقرارات مع حالات منع واضحة.
3. **Advanced Analytics:** إضافة محللات سلوكية وفك تشفير TLS.
4. **Hardening:** دمج سواقة WFP، حماية ضد العبث، إدارة أسرار.
5. **Observability:** لوحات تحكم، تكامل مع SIEM، تنبيهات لحظية.

## 🔐 أفضل الممارسات المقترحة
- تشغيل الخدمة بصلاحيات SYSTEM فقط عند الحاجة، وعزلها عن المستخدمين.
- استخدام قنوات آمنة لتحديث مؤشرات التهديد (TLS + توقيعات).
- تثبيت WinPcap/npCap (ويندوز) أو libpcap (لينكس) لضمان عمل الالتقاط الحي.
- تخزين السجلات في مسار محمي مع تدقيق الوصول.
- مراجعة قرارات المنع دوريًا لتقليل الإيجابيات الكاذبة.
- إضافة تكامل مع إدارة أسرار (DPAPI، Azure Key Vault، HashiCorp Vault) عند الانتقال للإنتاج.

## 🧰 أدوات مساعدة
- **تحليل الشبكة:** WFP, ETW, SharpPcap.
- **مؤشرات التهديد:** Abuse.ch, AlienVault OTX, YARA.
- **مراقبة النظام:** Sysmon, Windows Event Forwarding.

يمكنك استخدام هذا المخطط كقاعدة لبناء نظام متكامل ومن ثم تطويره تدريجيًا تبعًا للمراحل المذكورة.
