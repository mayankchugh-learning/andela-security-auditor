from datetime import datetime
from sqlalchemy import Integer, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.session import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    filename: Mapped[str] = mapped_column(String(255))
    file_type: Mapped[str] = mapped_column(String(10))  # "tf" or "yaml"
    risk_score: Mapped[float] = mapped_column(Float)
    risk_level: Mapped[str] = mapped_column(String(20))
    total_findings: Mapped[int] = mapped_column(Integer)
    scanned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"))
    rule_id: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    points: Mapped[int] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(Text)
    resource: Mapped[str] = mapped_column(String(255), nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
