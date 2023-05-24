PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS "samples" (
  sum TEXT PRIMARY KEY NOT NULL,
  path TEXT NOT NULL,
  first_bytes BLOB NOT NULL,
  src text NOT NULL,
  src_short TEXT AS (SUBSTR(REPLACE(src, 'raw-dataset/', ''), 0, INSTR(REPLACE(src, 'raw-dataset/', ''), '/'))) NOT NULL,
  size INTEGER NOT NULL,
  analysis_time INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS "binwalk" (
  sum TEXT PRIMARY KEY NOT NULL REFERENCES "samples" (sum) ON DELETE CASCADE,
  scan_types TEXT,
  linux_detected BOOLEAN,
  timeout BOOLEAN NOT NULL,
  CHECK (CASE
          WHEN timeout THEN (scan_types IS NULL AND linux_detected IS NULL)
          ELSE (linux_detected NOT NULL AND ((scan_types IS NULL AND NOT linux_detected)
                                              OR (scan_types NOT NULL)))
          END)
);

CREATE TABLE IF NOT EXISTS "entropy" (
    sum TEXT PRIMARY KEY NOT NULL REFERENCES "samples" (sum) ON DELETE CASCADE,
    numbers TEXT,
    median REAL,
    mean REAL,
    timeout BOOLEAN NOT NULL,
    CHECK (CASE
            WHEN timeout THEN (numbers IS NULL AND median IS NULL AND mean IS NULL)
            ELSE ((numbers IS NULL AND median IS NULL AND mean IS NULL)
                  OR (numbers NOT NULL AND median NOT NULL AND mean NOT NULL))
            END)
);

CREATE TABLE IF NOT EXISTS "padding" (
  sum TEXT PRIMARY KEY NOT NULL REFERENCES "samples" (sum) ON DELETE CASCADE,
  zero INTEGER,
  ff INTEGER
);

CREATE TABLE IF NOT EXISTS "r2_cpurec" (
    sum TEXT PRIMARY KEY NOT NULL REFERENCES "samples" (sum) ON DELETE CASCADE,
    arch TEXT,
    arch_supported BOOLEAN NOT NULL,
    functions TEXT,
    nfunctions INTEGER,
    timeout BOOLEAN NOT NULL,
    CHECK (CASE
            WHEN timeout THEN (arch NOT NULL and arch_supported AND functions IS NULL AND nfunctions IS NULL)
            ELSE (CASE arch
                  WHEN NULL THEN (functions IS NULL AND NOT arch_supported AND nfunctions IS NULL)
                  ELSE (arch_supported AND functions NOT NULL AND nfunctions NOT NULL)
                        OR (NOT arch_supported AND functions IS NULL AND nfunctions IS null)
                  END)
            END)
);

CREATE TABLE firmxray_base (
  sum TEXT NOT NULL PRIMARY KEY REFERENCES samples (sum) ON DELETE CASCADE,
  base_full INTEGER CHECK (base_full >= 0),
  base_nd INTEGER CHECK (base_nd >= 0)
);

CREATE TABLE IF NOT EXISTS "ghidra" (
  sum TEXT NOT NULL PRIMARY KEY REFERENCES "samples" (sum) ON DELETE CASCADE,
  base INTEGER,
  svc_addrs TEXT,
  n_svc_addrs INTEGER,
  xrefs TEXT,
  n_xrefs INTEGER,
  mcr TEXT,
  mem_writes TEXT,
  failed BOOLEAN NOT NULL,
  message TEXT,
  timeout BOOLEAN NOT NULL,
  CHECK (CASE
          WHEN timeout THEN (failed AND message IS NULL AND base IS NULL
                              AND svc_addrs IS NULL AND xrefs IS NULL
                              AND n_svc_addrs IS NULL AND n_xrefs IS NULL AND mcr IS NULL AND mem_writes)
          ELSE (CASE
                WHEN failed THEN (message NOT NULL AND base IS NULL
                                  AND svc_addrs IS NULL AND xrefs is null
                                  AND n_svc_addrs IS NULL AND n_xrefs IS NULL
                                  AND mcr IS NULL AND mem_writes IS NULL)
                ELSE (message IS NULL AND base NOT NULL AND svc_addrs NOT NULL
                      AND xrefs NOT NULL AND n_xrefs NOT NULL
                      AND mcr NOT NULL AND mem_writes NOT NULL)
                END)
          END));

CREATE VIEW firmxray AS SELECT * FROM "samples" WHERE src_short = 'firmxray';
