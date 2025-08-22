import importlib
import pkgutil
from scanner.plugins.base import BasePlugin

REGISTRY = {}

def detect_plugins():
    package = __name__
    for _, module_name, _ in pkgutil.iter_modules(__path__):
        module = importlib.import_module(f"{package}.{module_name}")
        if hasattr(module, "Plugin"):
            plugin = module.Plugin()
            if not isinstance(plugin, B):
                raise TypeError(f"Plugin {module_name} must inherit from BasePlugin")
            REGISTRY[module_name] = plugin

detect_plugins()