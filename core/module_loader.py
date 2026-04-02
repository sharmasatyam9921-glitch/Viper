"""VIPER Module Loader — clean optional import management.

Replaces 30+ try/except blocks with a declarative registry.
Each module is imported lazily and tracked for availability.
"""

import importlib
import logging
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("viper.module_loader")


class ModuleLoader:
    """Manages optional module imports with graceful degradation.

    Usage:
        loader = ModuleLoader()
        loader.register("recon.recon_engine", "ReconEngine")
        loader.load_all()

        if loader.available("ReconEngine"):
            engine = loader.get("ReconEngine")(verbose=True)
    """

    def __init__(self):
        self._registry: list[Tuple[str, list[str], str]] = []
        self._loaded: Dict[str, Any] = {}
        self._groups: Dict[str, bool] = {}

    def register(self, module_path: str, *names: str, group: str = ""):
        """Register module imports to attempt.

        Args:
            module_path: Dotted import path (e.g., "core.stealth")
            *names: Names to import from the module
            group: Optional group name for batch availability check
        """
        self._registry.append((module_path, list(names), group))

    def load_all(self) -> "ModuleLoader":
        """Attempt all registered imports. Failures are logged and skipped."""
        group_results: Dict[str, bool] = {}

        for module_path, names, group in self._registry:
            try:
                mod = importlib.import_module(module_path)
                for name in names:
                    obj = getattr(mod, name)
                    self._loaded[name] = obj
                if group:
                    group_results.setdefault(group, True)
            except (ImportError, AttributeError) as e:
                logger.debug("Optional module %s unavailable: %s", module_path, e)
                if group:
                    group_results[group] = False

        self._groups = group_results
        return self

    def get(self, name: str, default: Any = None) -> Any:
        """Get an imported object by name."""
        return self._loaded.get(name, default)

    def available(self, name: str) -> bool:
        """Check if a specific import succeeded."""
        return name in self._loaded

    def group_available(self, group: str) -> bool:
        """Check if all imports in a group succeeded."""
        return self._groups.get(group, False)

    def __contains__(self, name: str) -> bool:
        return name in self._loaded

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        if name in self._loaded:
            return self._loaded[name]
        raise AttributeError(f"Module '{name}' not loaded or unavailable")
