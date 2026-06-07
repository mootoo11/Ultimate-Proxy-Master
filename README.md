# Ultimate Proxy Master 🚀

An advanced, high-performance proxy scraper and checker. Automatically harvests thousands of free proxies from 80+ sources, verifies them using multithreading, and filters them by target URL (like Discord/Netflix) or country. Features an integrated SQLite database for easy management.

Developed by: [github.com/mootoo11](https://github.com/mootoo11)

---

## 🔥 Features
- **Scrape & Check**: Harvest thousands of free HTTP, SOCKS4, and SOCKS5 proxies from over 80+ sources and verify them concurrently.
- **Target Checker**: Check proxies against a specific target URL (e.g., Discord, Netflix, etc.).
- **Local List Checker**: Quickly check a list of proxies saved on your device (v21.0 FAST only).
- **View Stats**: Detailed intelligence on your live proxies (protocols, countries, types) stored in a local SQLite database.
- **Filter**: Filter your checked proxies by Country.
- **High Performance**: Uses `ThreadPoolExecutor` and background Daemon writers for fast checking without blocking I/O.

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mootoo11/Ultimate-Proxy-Master.git
   cd Ultimate-Proxy-Master
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🚀 Usage

The project includes two versions. We highly recommend using the Fast version for the best performance.

### Run the Fast Version (v21.0)
This version uses background Daemon queues to ensure maximum speed without IO blocking.
```bash
python sss.py
```

### Run the Standard Version (v20.0)
```bash
python pro.py
```

## 📜 Requirements
- Python 3.8+
- `requests`
- `colorama`
