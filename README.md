# Typosquatter Buster
[![Version-1.0](https://img.shields.io/badge/Version-1.0-green)](https://img.shields.io/badge/Version-1.1-green) [![Github License](https://img.shields.io/github/license/kaotickj/typosquatterBuster)](https://github.com/kaotickj/DigEm/blob/main/LICENSE) [![Language BASH](https://img.shields.io/badge/Language-Python-green)](https://www.gnu.org/software/python/)

[![Logo] (screen.png)
 This script detects typosquatting domains by generating typo variations of a given domain name, checking if they return a valid HTTP response, and running a WHOIS lookup to determine if the domain is registered, then generates an HTML report with the findings.

## Dependencies

- Python 3
- `python-whois` library. Install it using pip:

```
pip install python-whois
```

also be sure that you have the following standard libraries :
- os
- re
- requests
- tkinter
- datetime

### Usage

1. Clone the repository:
```
git clone https://github.com/kaotickj/typosquatterBuster.git
```

2. Navigate to the project directory:
```
cd typosquatterBuster
```

3. Run the script:
```
python typosquatterBuster.py
```

4. Enter a domain name in the provided field and click "Run Detection" to check for typosquatting domains. The script will display the variations being checked and generate an HTML report upon completion.
