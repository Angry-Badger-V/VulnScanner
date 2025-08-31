from abc import ABC, abstractmethod


class BasePlugin(ABC):
    """Base class for plugins."""

    name: str = "Unnamed Plugin"
    description: str = "No description provided."

    @abstractmethod
    def run(self, target: str, session, reconnaissance):
        """Run the vulnerability scan on the target.
        Must return a list of findings (or empty if none)."""
        pass
