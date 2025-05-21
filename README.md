# 🔍 0xD4 Advanced Takeover Scanner
**أداة متقدمة لاكتشاف ثغرات الاستيلاء على النطاقات والنطاقات الفرعية**  
*من فريق 0xD4 الأمني - "Knowledge is Power"*

![Banner](https://i.imgur.com/jQBPwmS.jpeg) *(صورة توضيحية للبانر)*

## 🌟 المميزات الرئيسية
- اكتشاف نقاط استيلاء على النطاقات (Subdomain Takeover)
- البحث عن نطاقات منتهية الصلاحية (Expired Domains)
- دعم متعدد الخيوط (Multi-threading) لمسح سريع
- تكامل مع محركات البحث (Dorking)
- تقارير بتنسيق JSON مع تفاصيل كاملة
- دعم جميع أنظمة التشغيل (Windows/Linux/macOS)

## 🛠️ متطلبات التشغيل
- Python 3.8 أو أحدث
- pip (أداة إدارة حزم بايثون)
- نظام تشغيل حديث (يفضل Linux للتشغيل الأمثل)


## التنصيب

```bash
1. git clone https://github.com/0xD4-Team/Takeover-Scanner.git
2. cd Takeover-Scanner
3. pip install -r requirements.txt
4. (اختياري) تثبيت الأداة بشكل دائم
pip install -e .

'''
## 📥 التنصيب والتهيئة

### 1. إنشاء بيئة افتراضية (مهم جداً)
```bash
python -m venv 0xD4-env
source 0xD4-env/bin/activate  # Linux/macOS
0xD4-env\Scripts\activate     # Windows
...
## 🚀 طريقة التشغيل
المسح الأساسي:
```bash
python3 scanner.py -d example.com
...
البحث عن نطاقات منتهية:
python3 scanner.py --find-expired "shop" -o results.json
مسح متقدم:
python3 scanner.py -l targets.txt -t 30 --deep -v
البحث عن نطاقات منتهية:
python3 scanner.py --find-expired "blog" -v

## 📞 التواصل
## 📧 البريد: iiqq_h@proton.me

## 📱 إنستجرام: @iiqq_h

## 🎵 تيك توك: @iiqq_h

## 💬 تيليجرام: https://t.me/xD4Team



