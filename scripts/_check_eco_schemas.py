import os

d = "<home>/.trae/skills/spz-gatekeeper-r-sequence/monitor-schemas"
for f in ["ECO-RESEARCH.json", "ECO-EDIT.json", "ECO-VERIFY.json", "ECO-DOC.json"]:
    p = os.path.join(d, f)
    size = os.path.getsize(p) if os.path.exists(p) else 0
    content = open(p).read() if os.path.exists(p) else "MISSING"
    print(f"=== {f} ({size} bytes) ===")
    print(content)
    print()
