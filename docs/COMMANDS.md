# BreachLens Commands

## doctor

```bash
breachlens doctor
```

Checks optional API keys, report directory and free/local modules.

## password

```bash
breachlens password
breachlens password -p 'Password123!'
```

Checks Pwned Passwords through k-anonymity.

## combo-scan

```bash
breachlens combo-scan combos.txt
breachlens combo-scan combos.txt --email user@example.com
breachlens combo-scan combos.txt --domain example.com
breachlens combo-scan combos.txt --domain example.com --check-passwords
```

Parses local authorized combo files and masks passwords.

## email

```bash
breachlens email user@example.com
breachlens email user@example.com --no-hibp
breachlens email user@example.com --local-file combos.txt
```

Combines optional HIBP, GitHub metadata and local file checks.

## domain

```bash
breachlens domain example.com
breachlens domain example.com --local-file combos.txt
breachlens domain example.com --hibp
```

Runs domain posture checks with optional sources.
