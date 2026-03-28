# 🛡️ Security Tools

Collection of security analysis tools for TheHive, IOC extraction, and incident response.

## 📁 Scripts

| Script | Description |
|--------|-------------|
| `thehive-analyzer.py` | Parse and analyze TheHive alerts |
| `ioc-extractor.py` | Extract IOCs from JSON and text |

## 🚀 Usage

```bash
# Analyze TheHive alert
python thehive-analyzer.py alert.json

# Extract IOCs from alert
python ioc-extractor.py alert.json

📋 Sample Alert Format

{
  "title": "Suspicious Connection Detected",
  "severity": 3,
  "status": "New",
  "tags": ["malware", "c2"],
  "artifacts": [
    {"dataType": "ip", "data": "185.130.5.253"},
    {"dataType": "domain", "data": "evil.com"}
  ]
}
