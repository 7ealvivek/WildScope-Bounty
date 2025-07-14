# WildScope-Bounty

```bash

git clone https://github.com/7ealvivek/WildScope-Bounty.git
cd WildScope-Bounty
pip3 install -r requirements.txt
```

```bash
shodan
tldextract
```

```bash
python3 shodan_subs.py -d example.com -s SHODAN_API_KEY
python3 shodan_subs.py -org "Fidelity National Information Services" -s SHODAN_API_KEY
```

## 🐉 Aggressive Mode (adds SSL based discovery)

```bash
python3 shodan_subs.py -org "Fidelity National Information Services" -s SHODAN_API_KEY --aggressive
```
