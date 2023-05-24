#!/usr/bin/env python3
import shutil
import sys
import logging
import time
import sys
import re
import os
import filecmp
import db
import file_analyses as analyses
from typing import Tuple, Optional, Generator, List
from pathlib import Path
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy import select, create_engine
import configparser
from dataclasses import dataclass

logging.basicConfig(format='%(asctime)s %(message)s')
#logging.getLogger("sqlalchemy.engine").setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)
LOGLEVEL = os.getenv('LOGLEVEL', 'INFO').upper()
logger.setLevel(LOGLEVEL)

@dataclass
class Timeouts:
    entropy: Optional[int]
    binwalk: Optional[int]
    radare2: Optional[int]
    ghidra_sigterm: Optional[int]
    ghidra_sigkill: Optional[int]

@dataclass
class Storage:
    sqlite_file: str
    processed_firmware_dir: str
    duplicates_dir: str
    collisions_dir: str

@dataclass
class Config:
    timeouts: Timeouts
    storage: Storage


def get_sessionmaker(where: str):
    engine = create_engine(where)
    dbsession: sessionmaker[Session] = sessionmaker(engine)
    return dbsession

def generate_new_name(origpath: Path, newdir: Path) -> Path:
    basename = re.sub('^.*/', '', str(origpath))
    basename = re.sub(r'\.ihex', '.bin', basename)
    basename = re.sub('[()]', '_', basename) # because ghidra sucks at quoting parens
    newname = newdir/basename
    if newname.exists():
        newname = newdir/f"{basename}_{int(time.time())}"
    return newname


def find_by_hash(h: str, session: Session) -> db.Sample | None:
    stmt = select(db.Sample).where(db.Sample.sum == h)
    results = session.scalars(stmt).all()

    assert len(results) < 2, 'Multiple results found for a hash, fix your database.'
    if len(results) == 1:
        return results[0]
    else:
        return None


def in_database(h: str, session: Session) -> Tuple[bool, db.Sample | None]:
    result: db.Sample | None = find_by_hash(h, session)
    return (result is not None and result.sum == h, result)


def check_prereqs() -> None:
    executables = ['file', 'bincopy', 'bgrep', 'timeout', 'radare2']
    for exec in executables:
        if not shutil.which(exec):
            print(f"File {exec} required, but not found or not executable. Please see README.md", file=sys.stderr)
            sys.exit(0)

    if not 'GHIDRA_HOME' in os.environ:
        print("Please set the environment variable $GHIDRA_HOME to your Ghidra installation directory.", file=sys.stderr)
        sys.exit(0)

    if not Path(f"{os.getenv('GHIDRA_HOME')}/support/analyzeHeadless").is_file():
        print("analyzeHeadless required, but not found in $GHIDRA_HOME", file=sys.stderr)
        sys.exit(0)


def is_duplicate(sha: str, dbsession: sessionmaker[Session]) -> db.Sample | None:
    with dbsession() as session:
        already_known, sample = in_database(sha, session)

    if already_known and sample is not None:
        return sample
    return None


def process_duplicate(filename: Path, duplicate_of: Path, *, duplicates_dir: Path, collisions_dir: Path) -> None:
    if filecmp.cmp(filename, duplicate_of):
        newname = generate_new_name(filename, duplicates_dir)
        filename.rename(newname)
        logger.info('DUPE')
    else:
        newname = generate_new_name(filename, collisions_dir)
        filename.rename(newname)
        logger.info('COLLISION')

def process_file(filename: Path, config: Config, dbsession: sessionmaker[Session], *, processed_firmware_dir: Path, duplicates_dir: Path, collisions_dir: Path) -> None:
    t_start: float = time.time()
    logger.info(f"Processing file {filename}")

    # Save the original path, to see the original source of the program
    orig_filename = filename
    is_ihex = analyses.is_ihex(filename)

    # IHEX files have to be converted before proceeding
    if is_ihex:
        logger.info('Converting file to binary')
        filename = analyses.convert_ihex(filename)
        logger.info(f"Temporary file: {filename}")
        logger.info(f"Removing original: {orig_filename}")
        orig_filename.unlink()

    # We use a sha256sum to identify files uniquely
    sum = analyses.sha256(filename)
    logger.info(f"Shasum {sum}")

    # Avoid processing duplicates; move them to a different directory
    if duplicate_of := is_duplicate(sum, dbsession):
        process_duplicate(filename, duplicate_of.path, duplicates_dir=duplicates_dir, collisions_dir=collisions_dir)
        return

    # Preliminary analysis
    file_size = analyses.size(filename)
    first_bytes: bytes = analyses.first_bytes(filename)

    logger.info('Entropy analysis')
    entropy: analyses.BinwalkEntropy = analyses.entropy(filename, timeout_sec=config.timeouts.entropy)
    db_entropy = db.Entropy(sum=sum,
                            numbers=db.prepare_obj(entropy.numbers),
                            median=entropy.median,
                            mean=entropy.mean,
                            timeout=entropy.timeout)


    logger.info('Padding search')
    file_padding: analyses.PaddingDict = analyses.padding(filename)
    db_padding = db.Padding(sum=sum,
                            zero=file_padding['zero'],
                            ff=file_padding['ff'])

    # Check if the file is non-Linux
    logger.info('Binwalk signature scan')
    bwalk: analyses.BinwalkSignature = analyses.binwalk_signature(filename, timeout_sec=config.timeouts.binwalk)
    db_bwalk = db.Binwalk(sum=sum,
                          scan_types=db.prepare_obj(bwalk.types),
                          linux_detected=bwalk.found_linux,
                          timeout=bwalk.timeout)

    # Determine the architecture
    logger.info('cpu_rec architecture scan')
    file_arch: Optional[List[str]] = analyses.arch(filename)

    # Verify that the file is firmware
    logger.info('radare2 analysis')
    if file_arch is not None:
        def determine_arch():
            first_arch = file_arch[0]
            first_radare_cpurec: analyses.R2Results = analyses.r2_cpurec(filename, first_arch, timeout_sec=config.timeouts.radare2)

            if first_arch is None or first_radare_cpurec.nfunctions is None or first_radare_cpurec.nfunctions == 0:
                for arch in file_arch[1:]:
                    radare_cpurec: analyses.R2Results = analyses.r2_cpurec(filename, arch, timeout_sec=config.timeouts.radare2)
                    if radare_cpurec.nfunctions is not None and radare_cpurec.nfunctions > 0:
                        return (arch, radare_cpurec)

            return (first_arch, first_radare_cpurec)


        arch, radare_cpurec = determine_arch()
    else:
        radare_cpurec = analyses.R2Results(arch_supported=False, timeout=False, functions=None)
        arch = None

    db_r2_cpurec = db.R2Cpurec(sum=sum,
                            arch=arch,
                            arch_supported=radare_cpurec.arch_supported,
                            functions=db.prepare_obj(radare_cpurec.functions),
                            nfunctions=radare_cpurec.nfunctions,
                            timeout=radare_cpurec.timeout)


    # Reverse engineer the sample
    logger.info('Ghidra RE analysis')
    if is_ihex:
        db_ghidra: Optional[db.Ghidra] = analyses.ghidra_analyze(filename, sum, arch, base=0, timeout_sec_term=config.timeouts.ghidra_sigterm, timeout_sec_kill=config.timeouts.ghidra_sigkill)
    else:
        db_ghidra: Optional[db.Ghidra] = analyses.ghidra_analyze(filename, sum, arch, timeout_sec_term=config.timeouts.ghidra_sigterm, timeout_sec_kill=config.timeouts.ghidra_sigkill)

    analysis_time = int(time.time() - t_start)
    logger.info(f'Processed in {analysis_time} seconds')

    # Create a new name for the file within the database
    newname = generate_new_name(orig_filename, processed_firmware_dir)

    logger.info('Adding sample to database')
    with dbsession() as session:
        fwfile = db.Sample(sum=sum,
                           path=str(newname),
                           first_bytes=first_bytes,
                           src=str(orig_filename),
                           size=file_size,
                           analysis_time=analysis_time,
                           binwalk=db_bwalk,
                           entropy=db_entropy,
                           padding=db_padding,
                           r2_cpurec=db_r2_cpurec,
                           ghidra=db_ghidra)

        session.add(fwfile)
        session.commit()

        filename.rename(newname)
        logger.info(f'renamed to {newname}')


def read_config() -> Config:
    config = configparser.ConfigParser()
    config_file = 'config.ini'

    if not Path(config_file).is_file():
        print(f"Expected config file {config_file}, but it was not found.", file=sys.stderr)
        sys.exit(1)

    config.read('config.ini')

    if not config.has_section('storage'):
        print("Config does not have a [storage] section, but it is required.", file=sys.stderr)
        sys.exit(1)

    try:
        storage = Storage(**{'sqlite_file': f"sqlite+pysqlite:///{config.get('storage', 'sqlite_file')}",
                             'processed_firmware_dir': config.get('storage', 'processed_firmware_dir'),
                             'duplicates_dir': config.get('storage', 'duplicates_dir'),
                             'collisions_dir': config.get('storage', 'collisions_dir')})
    except configparser.NoOptionError as o:
        print(o, file=sys.stderr)
        sys.exit(1)

    if not config.has_section('timeouts'):
        config.add_section('timeouts')

    try:
        timeouts = Timeouts(**{'binwalk': config.getint('timeouts', 'binwalk', fallback=None),
                               'radare2': config.getint('timeouts', 'radare2', fallback=None),
                               'ghidra_sigterm': config.getint('timeouts', 'ghidra_sigterm', fallback=None),
                               'ghidra_sigkill': config.getint('timeouts', 'ghidra_sigkill', fallback=None),
                               'entropy': config.getint('timeouts', 'entropy', fallback=None)})

    except KeyError as k:
        print(f"{k} not found in config file but expected", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"All timeout values should be integers. {e}", file=sys.stderr)
        sys.exit(1)

    return Config(timeouts, storage)


def main(ipt: Path | Generator[Path, None, None]):
    check_prereqs() # may exit
    config: Config = read_config() # may exit

    firmware_db = config.storage.sqlite_file
    dirs = { 'processed_firmware_dir': Path(config.storage.processed_firmware_dir),
            'duplicates_dir': Path(config.storage.duplicates_dir),
            'collisions_dir': Path(config.storage.collisions_dir)}

    for dir in dirs.values():
        if not dir.is_dir():
            dir.mkdir(parents=True)

    DbSession = get_sessionmaker(firmware_db)
    if isinstance(ipt, Generator):
        for fname in ipt:
            process_file(fname, config, DbSession, **dirs)
    elif isinstance(ipt, Path):
        process_file(ipt, config, DbSession, **dirs)

if __name__ == '__main__':
    assert len(sys.argv) == 2, "Usage: python3 pipeline.py /path/to/file_to_process"
    fname = Path(sys.argv[1])
    assert fname.exists(), f"File {fname} not found."
    main(fname)
