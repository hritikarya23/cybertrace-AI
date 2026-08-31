from pathlib import Path
import ast

def test_python_sources_parse():
    root=Path(__file__).resolve().parents[1]
    checked=0
    for folder in ("app","tests"):
        d=root/folder
        if d.exists():
            for p in d.rglob("*.py"):
                ast.parse(p.read_text(encoding="utf-8"))
                checked+=1
    assert checked >= 1
