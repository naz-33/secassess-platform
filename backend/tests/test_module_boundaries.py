import ast
from pathlib import Path


def test_modular_monolith_import_boundaries():
    """
    Statically inspects all files under app/modules/* using AST.
    Enforces the modular monolith architectural boundary rule:
    A module (e.g. recon) may ONLY import another module's public API (service.py or __init__.py).
    Direct imports of another module's models, repository, or router are strictly forbidden.
    """
    modules_dir = Path(__file__).resolve().parent.parent / "app" / "modules"
    assert modules_dir.exists() and modules_dir.is_dir(), f"Modules directory not found at {modules_dir}"

    module_dirs = [d for d in modules_dir.iterdir() if d.is_dir() and not d.name.startswith("__")]
    forbidden_leafs = {"models", "repository", "router"}
    violations = []

    for source_module_dir in module_dirs:
        source_module_name = source_module_dir.name

        for py_file in source_module_dir.rglob("*.py"):
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            except Exception as e:
                violations.append(f"Could not parse {py_file}: {e}")
                continue

            for node in ast.walk(tree):
                # Check 'from app.modules.<target>.<submodule> import ...'
                if isinstance(node, ast.ImportFrom) and node.module:
                    parts = node.module.split(".")
                    if len(parts) >= 3 and parts[0] == "app" and parts[1] == "modules":
                        target_module = parts[2]
                        if target_module != source_module_name:
                            # Cross-module import detected
                            if len(parts) >= 4 and parts[3] in forbidden_leafs:
                                violations.append(
                                    f"Boundary violation in {py_file.relative_to(modules_dir)}: "
                                    f"imports forbidden internal '{parts[3]}' from module '{target_module}'."
                                )
                            # Also check if imported names contain forbidden files (e.g. from app.modules.foo import models)
                            for alias in node.names:
                                if alias.name in forbidden_leafs:
                                    violations.append(
                                        f"Boundary violation in {py_file.relative_to(modules_dir)}: "
                                        f"imports forbidden internal symbol '{alias.name}' from module '{target_module}'."
                                    )

                # Check 'import app.modules.<target>.<submodule>'
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        parts = alias.name.split(".")
                        if len(parts) >= 4 and parts[0] == "app" and parts[1] == "modules":
                            target_module = parts[2]
                            if target_module != source_module_name and parts[3] in forbidden_leafs:
                                violations.append(
                                    f"Boundary violation in {py_file.relative_to(modules_dir)}: "
                                    f"imports forbidden internal '{parts[3]}' from module '{target_module}'."
                                )

    assert not violations, "Module boundary violations detected:\n" + "\n".join(violations)
