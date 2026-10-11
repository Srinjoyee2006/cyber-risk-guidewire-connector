"""
CyberRisk-Guidewire-Connector (CRGC)
Repositories Package Exports
"""

from app.repositories.ingestion_repository import IngestionRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository

__all__ = ["IngestionRepository", "VulnerabilityRepository"]
