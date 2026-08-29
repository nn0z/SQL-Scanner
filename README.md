# SQL-Injection 💉

An automated SQL injection testing to uncover backend database vulnerabilities.

## Features

- **Dynamic Page Crawling**: Uses headless Chromium via Playwright to navigate applications, parse DOM structures, and discover hidden endpoints or links.
- **Form & Parameter Extraction**: Automatically detects GET query strings and POST forms, intelligently populating input fields to maintain valid states during tests.
- **Advanced Error Analysis**: Evaluates HTTP responses using multi-tier regular expression pattern matching to distinguish actual database syntax errors from application errors or standard security blocks.
- **Colorized CLI Output**: Clear status codes, interactive payload logging, and an organized terminal summary dashboard.

---

## Installation

   ```
   pip install playwright
   ```
   ```
   playwright install chromium
   ```

---

## Disclaimer
*This tool is intended for authorized security auditing and educational purposes only. Do not use this tool against targets without prior explicit legal permission from the system owners.*
