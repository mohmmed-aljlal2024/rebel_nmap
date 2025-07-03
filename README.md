# RebelNmap - أداة مسح شبكات متقدمة مع إمكانيات التخفي  

![RebelNmap Banner](https://via.placeholder.com/800x200?text=RebelNmap+Advanced+Network+Scanner)  

**RebelNmap** هي أداة مسح شبكات متقدمة مستوحاة من **Nmap**، ولكن مع تحسينات في التخفي، الاختراق الأخلاقي، وجمع المعلومات. الأداة مكتوبة بلغة **Python 3** وتدعم تقنيات متقدمة مثل:  

- **مسح المنافذ** (SYN Stealth، TCP Connect، UDP، وغيرها)  
- **كشف نظام التشغيل** (OS Detection)  
- **اكتشاف الخدمات وتحديد إصداراتها**  
- **تقنيات التخفي** (تجزئة الحزم، IP Spoofing، MAC Spoofing)  
- **حصاد بيانات الاعتماد** (اختياري)  

---

## ⚙️ **متطلبات التشغيل**  

- Python 3.6 أو أحدث  
- نظام تشغيل **Linux / Windows / macOS** (يفضل Linux لأداء أفضل)  
- صلاحيات **Root/Admin** لبعض الميزات (مثل SYN Scan)  
- المكتبات المطلوبة:  

```bash
pip install scapy requests python-nmap colorama pywin32 (Windows فقط)