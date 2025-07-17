# __init__.py
from pathlib import Path
import importlib

dir = Path(__file__).parent

registry = {}

for file in dir.iterdir():
    if file.is_file():
        if not file.name.startswith("__") and file.name.endswith(".py"):
            # if file is python and a scanner add to registry
            try:
                module_name = file.stem
                module = importlib.import_module(f"{__package__}.{module_name}")

                # validate needed attributes
                has_name = hasattr(module, "name") and isinstance(module.name, str)
                has_description = hasattr(module, "description") and isinstance(module.description, str)
                has_run = hasattr(module, "run") and callable(module.run)

                if has_name and has_description and has_run:
                    registry[module.name] = module
                else:
                    missing = []
                    if not has_name:
                        missing.append("name")
                    if not has_description:
                        missing.append("description")
                    if not has_run:
                        missing.append("run()")

                    print(f"ERROR Failed to import {module_name}. Missing: {", ".join(missing)}")
            except Exception as e:
                print(f"ERROR Failed to import {module_name}: {e}")