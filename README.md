# Ultimate Proxy Master

An advanced, fast proxy scraper and checker developed by [github.com/mootoo11](https://github.com/mootoo11).

## Features
- **Scrape & Check**: Scrape thousands of free proxies from over 80+ sources and check them concurrently.
- **Target Checker**: Check proxies against a specific target URL (e.g., Discord, Netflix).
- **Check Existing List**: Quickly check a list of proxies saved on your device.
- **View Stats**: View detailed statistics of live proxies (protocols, countries, etc.) stored in a local SQLite database.
- **Filter**: Filter your checked proxies by country.
- **High Performance**: Uses ThreadPoolExecutor and background Daemon writers for fast checking without blocking I/O (v21.0).

## Installation

1. Clone the repository
2. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the fast version (v21.0):
```bash
python sss.py
```

Or the older version (v20.0):
```bash
python pro.py
```
