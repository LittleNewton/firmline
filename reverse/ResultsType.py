#!/usr/bin/env python3
from typing import TypedDict, List, Tuple

class ResultsMpuMemWrites(TypedDict):
    src: int
    to: int

class ResultsMpu(TypedDict):
    mcr: List[int]
    mem_writes: List[ResultsMpuMemWrites]

class Results(TypedDict):
    mpu: ResultsMpu
    xrefs: List[Tuple[str, str, str]]
    svc_addresses: List[int]
    base: int

class ResultsFileContents(TypedDict):
    results: str | Results
    ok: bool
    sha: str
