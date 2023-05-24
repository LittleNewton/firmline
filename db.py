# This file declares the tables in the database and their associated Python classes
from sqlalchemy.orm import Mapped, DeclarativeBase, mapped_column, relationship
from sqlalchemy.engine import Engine
from sqlalchemy import Column, Computed, Text, ForeignKey, BINARY, event
from typing import Optional, Any
from pathlib import Path
import json

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

def prepare_obj(obj: Any) -> Optional[str]:
    if obj is None:
        return None
    return json.dumps(obj)

class Base(DeclarativeBase):
    pass


class Sample(Base):
    __tablename__ = 'samples'
    sum: Mapped[str] = mapped_column(Text, primary_key=True)
    path: Mapped[Path] = mapped_column(Text)
    first_bytes: Mapped[bytes] = mapped_column(BINARY)
    src: Mapped[str] = mapped_column(Text)
    src_short = Column('src_short', Text, Computed('SUBSTR(src, 1, INSTR(src, "/") -1)', persisted=True), nullable=False)
    size: Mapped[int]
    analysis_time: Mapped[int]

    # child tables:
    binwalk: Mapped['Binwalk'] = relationship(back_populates='sample')
    entropy: Mapped['Entropy'] = relationship(back_populates='sample')
    padding: Mapped['Padding'] = relationship(back_populates='sample')
    r2_cpurec: Mapped['R2Cpurec'] = relationship(back_populates='sample')
    firmxray_base: Mapped['FXRBase'] = relationship(back_populates='sample')
    ghidra: Mapped['Ghidra'] = relationship(back_populates='sample')

    def __repr__(self):
        return f'<Sample {self.sum}>'


class Binwalk(Base):
    __tablename__ = 'binwalk'
    sum: Mapped[str] = mapped_column(Text, ForeignKey('samples.sum'), primary_key=True)
    sample: Mapped['Sample'] = relationship(back_populates='binwalk')
    scan_types: Mapped[Optional[str]] = mapped_column(Text)
    linux_detected: Mapped[Optional[bool]]
    timeout: Mapped[bool]

class Entropy(Base):
    __tablename__ = 'entropy'
    sum: Mapped[str] = mapped_column(Text, ForeignKey('samples.sum'), primary_key=True)
    sample: Mapped['Sample'] = relationship(back_populates='entropy')
    numbers: Mapped[Optional[str]] = mapped_column(Text)
    median: Mapped[Optional[float]]
    mean: Mapped[Optional[float]]
    timeout: Mapped[bool]

class Padding(Base):
    __tablename__ = 'padding'
    sum: Mapped[str] = mapped_column(Text, ForeignKey('samples.sum'), primary_key=True)
    sample: Mapped['Sample'] = relationship(back_populates='padding')
    zero: Mapped[Optional[str]] = mapped_column(Text)
    ff: Mapped[Optional[str]] = mapped_column(Text)


class R2Cpurec(Base):
    __tablename__ = 'r2_cpurec'
    sum: Mapped[str] = mapped_column(Text, ForeignKey('samples.sum'), primary_key=True)
    sample: Mapped['Sample'] = relationship(back_populates='r2_cpurec')
    arch: Mapped[Optional[str]] = mapped_column(Text)
    arch_supported: Mapped[bool]
    functions: Mapped[Optional[str]] = mapped_column(Text)
    nfunctions: Mapped[Optional[int]]
    timeout: Mapped[bool]

class FXRBase(Base):
    __tablename__ = 'firmxray_base'
    sum: Mapped[str] = mapped_column(Text, ForeignKey('samples.sum'), primary_key=True)
    sample: Mapped['Sample'] = relationship(back_populates='firmxray_base')
    base_full: Mapped[Optional[int]]
    base_nd: Mapped[Optional[int]]

class Ghidra(Base):
    __tablename__ = 'ghidra'
    sum: Mapped[str] = mapped_column(Text, ForeignKey('samples.sum'), primary_key=True)
    sample: Mapped['Sample'] = relationship(back_populates='ghidra')
    base: Mapped[Optional[int]]
    svc_addrs: Mapped[Optional[str]]
    n_svc_addrs: Mapped[Optional[int]]
    xrefs: Mapped[Optional[str]]
    n_xrefs: Mapped[Optional[int]]
    mcr: Mapped[Optional[str]]
    mem_writes: Mapped[Optional[str]]
    message: Mapped[Optional[str]]
    failed: Mapped[bool]
    timeout: Mapped[bool]

    def __str__(self):
        return f"<Ghidra sum {self.sum} base {self.base}>"
