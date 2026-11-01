#!/bin/bash
set -x
cd <home>/.trae/skills/spz-gatekeeper-r-sequence
CLI="./gatekeeper-cli.sh"
STATE="<home>/.trae/skills/spz-gatekeeper-r-sequence/.gatekeeper.state"

# Fix checksum
python3 -c "
import json,hashlib
d=json.load(open('$STATE'))
gd=d['gate_data']
h=hashlib.sha256(json.dumps(gd,sort_keys=True).encode()).hexdigest()[:16]
d['_checksum']=h
json.dump(d,open('$STATE','w'),indent=2)
print('checksum ok')
"

# Test Python tmpfile write directly
echo "--- Test Python tmpfile write ---"
v='{"F1":"PASS","F2":"PASS"}'
tf=$(mktemp)
TF="$tf" V="$v" python3 -c "import os;open(os.environ['TF'],'w').write(os.environ['V'])"
echo "File size: $(wc -c < $tf)"
echo "Hex dump:"
xxd "$tf" | head -3
echo "Python can parse:"
python3 -c "import json; json.loads(open('$tf').read().strip()); print('OK')"

# Test adjudicate
echo "--- Running adjudicate ---"
bash "$CLI" adjudicate --verdicts '{"F1":"PASS","F2":"PASS"}' --score 0.90 --decision "test" --concessions '{}'
echo "exit code: $?"

# Check state
python3 -c "
import json
d=json.load(open('$STATE'))
ar=d.get('gate_data',{}).get('adjudicate_records',[])
cl=d.get('gate_data',{}).get('human_calibration_log',[])
print('adjudicate_records:', len(ar))
print('human_calibration_log:', len(cl))
"
