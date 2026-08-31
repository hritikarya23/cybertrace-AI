import ast
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
errors=[]
for folder in ("app","tests"):
    d=ROOT/folder
    if d.exists():
        for p in d.rglob("*.py"):
            try: ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
            except SyntaxError as e: errors.append(f"{p}: {e}")
if errors:
    print("\n".join(errors)); raise SystemExit(1)
print("AST validation passed.")
