
import re

risks = {'High': [], 'Medium': [], 'Low': []}

log_path = '/var/log/lynis.log'  # Full path for sudo runs

try:
    with open(log_path, 'r') as f:
        content = f.read()
except FileNotFoundError:
    print("Log missing—run 'sudo lynis audit system' first!")
    exit(1)

# Parse line-by-line for Lynis format: [tag] text or Suggestion: lines
for line in content.split('\n'):
    line = line.strip()
    if not line:
        continue
    if line.startswith('['):  # e.g., [category] Name or [!] Warning: ...
        match = re.match(r'$$ (.*?) $$\s*(.*)', line)
        if match:
            tag, text = match.groups()
            if '!' in tag or 'warning' in text.lower():
                risks['High'].append(f"{tag}: {text}")
            elif 'suggestion' in text.lower():
                risks['Medium'].append(f"{tag}: {text}")
            else:
                risks['Low'].append(f"{tag}: {text}")  # Info items
    elif 'suggestion:' in line.lower():
        risks['Medium'].append(line)

# Output top 3 per level
for level, items in risks.items():
    print(f"\n{level} Risks:")
    for item in items[:3]:
        print(f"  - {item}")

# Summary
print(f"\nTotal: {len(risks['High'])} High, {len(risks['Medium'])} Medium, {len(risks['Low'])} Low")
