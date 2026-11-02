import json, os

sf = '<home>/.trae/skills/spz-gatekeeper-r-sequence/state/state.json'
if os.path.exists(sf):
    d = json.load(open(sf))
    rej = d.get('gate_data',{}).get('rejected_edits',[])
    av = d.get('gate_data',{}).get('_ACCESS_VIOLATIONS',[])
    keys_hits = [v for v in av if '.keys/' in str(v.get('path',''))]
    print(f'rejected_edits count: {len(rej)}')
    print(f'_ACCESS_VIOLATIONS count: {len(av)} ({len(keys_hits)} keys-hits)')
    print(f'stored entropy_rate: {d.get("gate_data",{}).get("entropy_rate","N/A")}')
    print(f'current stage: {d.get("stage","IDLE")}')
    print()
    print('=== GAP ANALYSIS ===')
    print('R4 entropy: computed from rejected_edits (editor violations)')
    print('R7 G7:     tracks _ACCESS_VIOLATIONS with .keys/ paths (file access)')
    print('STATUS:    NOT connected — separate violation counters')
    print('IMPACT:    .keys/ compromise detected by R7 but R4 unaware')
    # Check if R4 advance logic connects to R7
    r4_lines = open('<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh').readlines()
    r4_mentions_access = any('_ACCESS_VIOLATIONS' in l and 'entropy' in l.lower() for l in r4_lines)
    print(f'R4 code mentions _ACCESS_VIOLATIONS in entropy context: {r4_mentions_access}')
else:
    print('No state file found at', sf)
