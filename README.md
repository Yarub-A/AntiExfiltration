# DataExfiltrationShield

منصة مرجعية لمكافحة تسريب البيانات تتكوّن من Agent خفيف، محلل مركزي، ومخزن أدلة جنائية، مع واجهة إدارة آمنة.

## هيكل المستودع

```
.
├─ ManagementAPI/           # خدمة الإدارة (ASP.NET Core 8)
│  ├─ Models/               # عقود API والكيانات الداخلية
│  ├─ Services/             # تطبيقات التخزين المؤقت داخل الذاكرة
│  ├─ appsettings.json      # تهيئة افتراضية بدون أسرار حساسة
│  └─ Dockerfile            # صورة إنتاجية للخدمة
├─ deploy/
│  └─ k8s/                  # ملفات نشر Kubernetes (Namespace, Deployments, Ingress)
├─ docs/
│  └─ architecture.md       # ملخص معماري للمكوّنات الرئيسية
├─ openapi/
│  └─ managementapi.yaml    # مواصفة OpenAPI الكاملة للـ ManagementAPI
└─ docker-compose.yml       # تشغيل محلي لخدمات الحافلة والـ ManagementAPI
```

## متطلبات مبدئية
- **Docker 24+** لتشغيل البيئة المحلية أو بناء الصورة.
- **.NET 8 SDK** إذا رغبت في تشغيل الخدمة مباشرة على الجهاز المضيف.
- متغيرات بيئة آمنة: `JWT_SECRET`، `MANAGEMENT_API_KEY` (تستخدم لتوليد رمز JWT).

## خطوات التشغيل محليًا
1. أنشئ ملف `.env` في الجذر:
   ```bash
   cat <<EOF > .env
   JWT_SECRET="استبدل_بقيمة_قوية_طولها_32_بايت"
   MANAGEMENT_API_KEY="api-key-مؤقت"
   EOF
   ```
2. شغّل الحاويات:
   ```bash
   docker compose up --build
   ```
3. جرّب الحصول على رمز وصول:
   ```bash
   curl -X POST http://localhost:8443/v1/auth/token \
     -H "Content-Type: application/json" \
     -d '{"clientId":"cli-sample","apiKey":"api-key-مؤقت"}'
   ```
4. استخدم الرمز في طلبات لاحقة (مثال إرسال حدث):
   ```bash
   curl -X POST http://localhost:8443/v1/events \
     -H "Authorization: Bearer <TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"agentId":"agent-01","timestamp":"2024-01-01T00:00:00Z","type":"network","payload":{"bytesOut":1024}}'
   ```

> **تنبيه أمني:** الصورة الحالية تعتمد على مخازن داخلية (InMemory). لا تستخدمها في الإنتاج بدون استبدالها بمخازن آمنة (PostgreSQL/Redis) وإضافة طبقة تحقق صلاحيات أدق.

## تشغيل الخدمة عبر .NET مباشرة
```bash
dotnet restore ManagementAPI/ManagementAPI.csproj
dotnet run --project ManagementAPI/ManagementAPI.csproj
```
ستجد الخدمة على `https://localhost:5001` افتراضيًا، ويمكن تعديل المنافذ عبر `ASPNETCORE_URLS`.

## نشر Kubernetes
1. عدّل قيم الأسرار والصور في ملفات `deploy/k8s`.
2. طبّق الملفات بالتسلسل:
   ```bash
   kubectl apply -f deploy/k8s/00-namespace-and-secret.yaml
   kubectl apply -f deploy/k8s/10-management-api-deployment.yaml
   kubectl apply -f deploy/k8s/20-agent-daemonset.yaml
   kubectl apply -f deploy/k8s/30-forensics-statefulset.yaml
   kubectl apply -f deploy/k8s/40-services-and-ingress.yaml
   ```
3. فعّل TLS عبر Ingress Controller مناسب (Nginx/Traefik) وأضف شهادات صالحة.

## اختبارات مبدئية
- أضف لاحقًا اختبارات وحدات باستخدام `xUnit` و`WebApplicationFactory` لمحاكاة استدعاءات API.
- استخدم أدوات مثل `k6` أو `Vegeta` لاختبارات الضغط على مسار `/v1/events`.
- اربط `dotnet test` و`docker build` مع CI (GitHub Actions) لمراقبة جودة التغيير.

## خارطة طريق قصيرة
1. **استبدال التخزين داخل الذاكرة** بقاعدة بيانات ثابتة وتدقيق سجلات (Audit Trail).
2. **تكامل SIEM** عبر موصل CEF/STIX في مجلد `Integrations/`.
3. **تضمين MemoryScanner آمن** داخل Agent مع واجهات REST/gRPC.
4. **تحسين الأمان** بإضافة سياسات RBAC وتوليد مفاتيح قصيرة العمر عبر KMS.
