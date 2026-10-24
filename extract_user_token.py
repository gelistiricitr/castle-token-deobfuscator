import json

with open(r'C:\Users\Administrator\.gemini\antigravity-ide\brain\ce928434-a38f-4d43-b16e-bd03778c4dc1\.system_generated\logs\transcript_full.jsonl', 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        if '"type":"USER_INPUT"' in line and 'uq1seNrd' in line:
            obj = json.loads(line)
            content = obj.get('content', '')
            print('Full user prompt length:', len(content))
            # Find token starting with uq1seNrd
            start = content.find('uq1seNrd')
            # The token goes until whitespace or quote
            end = start
            while end < len(content) and content[end] not in ' \r\n"\'`':
                end += 1
            tok = content[start:end].strip()
            print('Extracted token length:', len(tok))
            with open(r'c:\Users\Administrator\Desktop\Castle Tw Web\original_user_token.txt', 'w', encoding='utf-8') as tf:
                tf.write(tok)
            print('Saved original_user_token.txt successfully!')
            break
