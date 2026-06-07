<div align="center">
  <h1>🚀 Ultimate Proxy Master</h1>
  <p>An enterprise-grade, ultra-fast proxy scraper and checker developed by <a href="https://github.com/mootoo11">@mootoo11</a></p>
</div>

---

## 🔥 Enterprise Features
- **High-Speed Scrape & Check**: Harvest thousands of free HTTP, SOCKS4, and SOCKS5 proxies from over 80+ premium sources and verify them concurrently.
- **Target URL Verification**: Ensure proxies work against specific endpoints (e.g., Discord, Netflix, Google).
- **Offline List Checking**: Import your own premium proxy lists and verify them rapidly.
- **Database Intelligence**: Stores comprehensive data (speed, anonymity, protocol, country) in a robust local SQLite database.
- **Advanced Filtering**: Export and filter live proxies by specific Country Codes.
- **Asynchronous Architecture**: Built with `ThreadPoolExecutor` and background Daemon queues to ensure maximum throughput with zero I/O blocking.

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mootoo11/Ultimate-Proxy-Master.git
   cd Ultimate-Proxy-Master
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🚀 Quick Start

Run the primary application (Engine v21.0 - High Performance):
```bash
python proxy_master.py
```

*Note: For backward compatibility, the older synchronous version is included as `legacy_version.py`.*

## 📜 System Requirements
- Python 3.8+
- `requests`
- `colorama`
