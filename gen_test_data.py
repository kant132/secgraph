"""从真实 webgoat codegraph.db 查询数据，生成测试用的 mock 数据。

查询多个真实 nodeid（SQLi + XSS + 不可达），输出 Python 代码可直接粘贴到测试文件。

用法: py -3 gen_test_data.py > tests/_test_data.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from src.codegraph import CodegraphClient

DB = r"D:\jar\webgoat\.codegraph\codegraph.db"
SOURCES = r"D:\jar\webgoat"

# 要查的真实 nodeid
NODEIDS = {
    "SQLI_INJECTABLE": "method:997b7879a35fb0d978b1dec266c18e63",
    "SQLI_REGISTER": "method:647d162fdf923cdfbc8d4343d418e51e",
    "XSS_COMPLETED": "method:7ee6991165334a5b9998084beba380b5",
    "UNREACHABLE": "method:1a6f33df415e87274a6d8b8b3c777423",
}


def py_str(s: str) -> str:
    """Python 字符串转义"""
    return json.dumps(s, ensure_ascii=False)


def main():
    cg = CodegraphClient(DB)

    print('"""自动生成的测试数据 — 来自真实 webgoat codegraph.db"""')
    print("from src.state import MethodNode, FieldNode, FileAuditTask")
    print()

    for name, nid in NODEIDS.items():
        # 查 node 元数据
        row = cg._conn.execute(
            "SELECT id, qualified_name, name, signature, file_path, start_line, end_line "
            "FROM nodes WHERE id=?", (nid,)
        ).fetchone()
        if not row:
            print(f"# {name}: node not found")
            continue

        # 查 fields
        fields = cg.list_fields_by_nodeid(nid)
        # 查 method body
        from src.state import MethodNode
        m = MethodNode(id=row["id"], qualified_name=row["qualified_name"], name=row["name"],
                       signature=row["signature"], file_path=row["file_path"],
                       start_line=row["start_line"], end_line=row["end_line"])
        body = cg.get_method_body(SOURCES, m)
        # 查 callees
        callees = cg.get_callee_bodies(SOURCES, nid)
        # 查 route 可达
        reachable = cg.is_route_reachable(nid)
        # 查 Q5 调用链
        chains = cg.get_call_chain_to_route(nid)
        # 查 chain bodies
        chain_bodies = {}
        if chains:
            chain_bodies = cg.get_chain_bodies(SOURCES, chains[0]["chain_ids"])

        # 输出 Python 代码
        print(f"# {'='*60}")
        print(f"# {name} — {row['qualified_name']}")
        print(f"# {'='*60}")
        print(f"{name}_METHOD = MethodNode(")
        print(f'    id={py_str(row["id"])},')
        print(f'    qualified_name={py_str(row["qualified_name"])},')
        print(f'    name={py_str(row["name"])},')
        print(f'    signature={py_str(row["signature"])},')
        print(f'    file_path={py_str(row["file_path"])},')
        print(f'    start_line={row["start_line"]}, end_line={row["end_line"]},')
        print(f')')
        print()

        # Fields
        print(f"{name}_FIELDS = [")
        for f in fields:
            print(f'    FieldNode(id={py_str(f.id)}, qualified_name={py_str(f.qualified_name)}, name={py_str(f.name)}, start_line={f.start_line}, end_line={f.end_line}),')
        print(']')
        print()

        # Method body
        print(f"{name}_BODY = {py_str(body)}")
        print()

        # Callees
        print(f"{name}_CALLEES = {{")
        for cid, cbody in callees.items():
            print(f'    {py_str(cid)}: {py_str(cbody)},')
        print('}')
        print()

        # Reachable
        print(f"{name}_REACHABLE = {reachable}")
        print()

        # Q5 chain
        if chains:
            chain = chains[0]
            print(f"{name}_CHAIN = {json.dumps(dict(chain), ensure_ascii=False, indent=2)}")
        else:
            print(f"{name}_CHAIN = []  # 不可达")
        print()

        # Chain bodies
        print(f"{name}_CHAIN_BODIES = {{")
        for cid, cbody in chain_bodies.items():
            print(f'    {py_str(cid)}: {py_str(cbody)},')
        print('}')
        print()

        # Task
        print(f"{name}_TASK = FileAuditTask(")
        print(f'    file_path={py_str(row["file_path"])},')
        print(f'    node_id={py_str(nid)},')
        print(f'    fields={name}_FIELDS,')
        print(f'    method_bodies={{{py_str(nid)}: {name}_BODY}},')
        print(f'    calls={name}_CALLEES,')
        print(f')')
        print()

    cg.close()


if __name__ == "__main__":
    main()
