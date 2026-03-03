from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class ScanResult(Base):
    __tablename__ = "scan_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(String, index=True)
    threat_score: Mapped[int] = mapped_column(Integer)
    assessment: Mapped[str] = mapped_column(String)
    checks_json: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[str] = mapped_column(String)
