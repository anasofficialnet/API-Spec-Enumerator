import os
import re

replacements = {
    # Hex colors
    r'(?i)#00E676': '#6366F1',  # Primary green -> Indigo
    r'(?i)#080C0A': '#04070D',  # Base bg
    r'(?i)#081018': '#090E17',  # Dark bg
    r'(?i)#04070d': '#030509',  # Darker bg
    r'(?i)#0D1410': '#0B1120',  # Surface bg
    r'(?i)#111A16': '#111827',  # Surface2 bg
    r'(?i)#5A7A65': '#94A3B8',  # Muted text
    r'(?i)#426055': '#64748B',  # Dim text in CSS
    r'(?i)#2E4A38': '#475569',  # Dim text in TSX
    r'(?i)#E8F5E9': '#F8FAFC',  # Main text
    r'(?i)#85f7ba': '#A5B4FC',  # Light green text -> Light indigo
    r'(?i)#8cb4a2': '#94A3B8',  # CSS muted text
    
    # RGB combinations (comma separated, handling arbitrary spaces)
    r'0,\s*230,\s*118': '99, 102, 241', # Primary rgb
    r'8,\s*12,\s*10': '4, 7, 13',       # Base rgb
    r'13,\s*20,\s*16': '11, 17, 32',    # Surface rgb
    r'90,\s*122,\s*101': '148, 163, 184', # Muted text rgb
}

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original_content = content
    for pattern, replacement in replacements.items():
        content = re.sub(pattern, replacement, content)

    if content != original_content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Updated {filepath}")

src_dir = 'c:/Users/Thinkpad/Desktop/API-Spec-Enumerator/src'
config_file = 'c:/Users/Thinkpad/Desktop/API-Spec-Enumerator/tailwind.config.js'

for root, dirs, files in os.walk(src_dir):
    for file in files:
        if file.endswith(('.tsx', '.ts', '.css')):
            process_file(os.path.join(root, file))

if os.path.exists(config_file):
    process_file(config_file)
