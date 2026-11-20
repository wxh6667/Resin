ALTER TABLE platforms ADD COLUMN exclude_hosting INTEGER NOT NULL DEFAULT 0 CHECK (exclude_hosting IN (0, 1));
ALTER TABLE platforms ADD COLUMN asn_excludes_json TEXT NOT NULL DEFAULT '[]';
