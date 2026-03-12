"""Base class for all page handlers."""
from abc import ABC, abstractmethod
import requests

class BaseHandler(ABC):
    name: str = ""
    @abstractmethod
    def handle(self, url, session, detection, **kwargs):
        ...
