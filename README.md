# 🔍 0xD4 Advanced Takeover Scanner  
**أداة متقدمة لاكتشاف ثغرات الاستيلاء على النطاقات والنطاقات الفرعية**  
*من تطوير فريق 0xD4 الأمني - "Knowledge is Power"*

![Banner](https://i.imgur.com/N4Bi2oG.jpeg)

---

## 🌟 المميزات الرئيسية
- ✅ اكتشاف استيلاء على النطاقات الفرعية (Subdomain Takeover)
- 🔍 البحث عن نطاقات منتهية الصلاحية (Expired Domains)
- 🚀 دعم تعدد الخيوط (Multi-threading) لمسح سريع وكفء
- 🧠 تكامل مع محركات البحث (Google Dorking)
- 📦 تقارير بتنسيق JSON منظمة وسهلة التحليل
- 🖥️ دعم جميع أنظمة التشغيل (Windows / Linux / macOS)

---

## 🛠️ متطلبات التشغيل
- Python 3.8 أو أحدث  
- pip (مدير الحزم الخاص ببايثون)  
- نظام تشغيل حديث (الأداء الأمثل على Linux)  

---

## 📥 خطوات التنصيب

```bash
git clone https://github.com/0xD4-Team/Takeover-Scanner.git
cd Takeover-Scanner
pip install -r requirements.txt
```

### (اختياري) تثبيت الأداة بشكل دائم:

```bash
pip install -e .
```

---

## 📦 إنشاء بيئة افتراضية
```bash
python -m venv 0xD4-env
source 0xD4-env/bin/activate      # على Linux/macOS
0xD4-env\Scripts\activate         # على Windows
```

---

## 🚀 طريقة الاستخدام

### 🔎 مسح نطاق محدد:
```bash
python3 scanner.py -d example.com
```

### 📜 البحث عن نطاقات منتهية تحتوي كلمة معينة:
```bash
python3 scanner.py --find-expired "shop" -o results.json
```

### 🧨 مسح متقدم من ملف نصي:
```bash
python3 scanner.py -l targets.txt -t 30 --deep -v
```

### 🧬 بحث سريع عن نطاقات منتهية:
```bash
python3 scanner.py --find-expired "blog" -v
```

---

## 📡 للتواصل معانا (لو عندك أي استفسار أو حابب تشارك)

- 📧 البريد الإلكتروني: [iiqq_h@proton.me](mailto:iiqq_h@proton.me)  
- 📱 إنستجرام: [@iiqq_h](https://instagram.com/iiqq_h)  
- 🎵 تيك توك: [@iiqq_h](https://tiktok.com/@iiqq_h)  
- 💬 تيليجرام: [https://t.me/xD4Team](https://t.me/xD4Team)

---


