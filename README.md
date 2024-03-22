# Typosquatter Buster
 This script detects typosquatting domains by generating typo variations of a given domain name, checking if they return a valid HTTP response, and running a WHOIS lookup to determine if the domain is registered, then generates an HTML report with the findings.
### Dependencies
Whois for python:

```
pip3 install python-whois
```

also be sure that you have the following standard libraries :
- os
- re
- requests
- tkinter
- datetime
 