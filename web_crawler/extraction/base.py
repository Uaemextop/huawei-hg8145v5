"""Base class for all link extractors."""
from abc import ABC, abstractmethod

class BaseExtractor(ABC):
    name: str = ""
    @abstractmethod
    def extract(self, content, url, base):
        ...
    @abstractmethod
    def can_handle(self, content_type, url):
        ...
