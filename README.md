# FirmLine: a Generic Pipeline for Large-Scale Analysis of Non-Linux Firmware

## Prerequisites

```sh
git submodule update --init
cd binwalk && python setup.py install && cd ..
pip install -r requirements.txt
(cd bgrep && sudo make install)
(cd radare2 && sys/install.sh)
```

## Quickstart
1. Install the prerequisites & ensure all submodules are cloned.
2. Customize `config.ini` as needed.
3. Initialize an SQLite3 database from `schema.sql` (e.g. `sqlite3 fwdb.db < schema.sql`).
4. Execute `pipeline.py` with a file, e.g. `python3 pipeline.py /path/to/file`. Optionally parallelize with e.g. GNU Parallel.

## Important files in this repo
- [config.ini](config.ini): configuration for the pipeline
- [pipeline.py](pipeline.py): main entrypoint for FirmLine
- [file\_analyses.py](file_analyses.py): various analysis functions used by the pipeline
- [db.py](db.py): database interaction via [SQLAlchemy](https://www.sqlalchemy.org/)
- [find-files.sh](find-files.sh): identifies files to be processed from the raw datasets described in the paper
- [fwdb.db.txz](fwdb.db.txz): archive (compressed with XZ) containing the database of firmware analysis results
- [processed-firmware.txz](processed-firmware.txz): archive (compressed with XZ) containing the actual firmware samples
- [schema.sql](schema.sql): definition of SQLite database schema
- [reverse/](reverse/): files to run code analysis via Ghidra
