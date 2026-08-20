//! sqlite store for fingerprints, with a tiny LSH band index so queries don't
//! have to compare against every row.

use anyhow::Result;
use fnprint_sig::{Fingerprint, SIG_LEN};
use rusqlite::{params, Connection, OptionalExtension};

// b bands of r rows. b*r must equal SIG_LEN.
pub const BAND_ROWS: usize = 4;
pub const BANDS: usize = SIG_LEN / BAND_ROWS;
// every legit signature is exactly SIG_LEN u64s. a stored blob of any other
// size is corrupt or crafted, so we never select or decode it. this also caps
// how big a blob a malicious corpus db can make us allocate.
const SIG_BYTES: i64 = (SIG_LEN * 8) as i64;

pub struct Db {
    pub conn: Connection,
}

#[derive(Clone)]
pub struct FuncRec {
    pub id: i64,
    pub binary: String,
    pub name: Option<String>,
    pub entry: u64,
    pub source: String,
    pub fp: Fingerprint,
}

impl Db {
    pub fn open(path: &str) -> Result<Db> {
        let conn = Connection::open(path)?;
        Self::init(&conn)?;
        Ok(Db { conn })
    }

    pub fn open_memory() -> Result<Db> {
        let conn = Connection::open_in_memory()?;
        Self::init(&conn)?;
        Ok(Db { conn })
    }

    fn init(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS funcs(
                id INTEGER PRIMARY KEY,
                binary TEXT NOT NULL,
                name TEXT,
                entry INTEGER NOT NULL,
                source TEXT NOT NULL,
                complexity INTEGER NOT NULL,
                shingles INTEGER NOT NULL,
                capped INTEGER NOT NULL,
                sig BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bands(
                band INTEGER NOT NULL,
                key INTEGER NOT NULL,
                func_id INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS bands_lookup ON bands(band, key);",
        )?;
        Ok(())
    }

    pub fn insert(
        &self,
        binary: &str,
        name: Option<&str>,
        entry: u64,
        source: &str,
        fp: &Fingerprint,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO funcs(binary,name,entry,source,complexity,shingles,capped,sig)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                binary,
                name,
                entry as i64,
                source,
                fp.complexity as i64,
                fp.shingles as i64,
                fp.capped as i64,
                encode_sig(&fp.sig)
            ],
        )?;
        let id = self.conn.last_insert_rowid();
        for (band, key) in fp.band_keys(BAND_ROWS).into_iter().enumerate() {
            self.conn.execute(
                "INSERT INTO bands(band,key,func_id) VALUES(?1,?2,?3)",
                params![band as i64, key as i64, id],
            )?;
        }
        Ok(id)
    }

    pub fn all(&self) -> Result<Vec<FuncRec>> {
        let mut st = self.conn.prepare(
            "SELECT id,binary,name,entry,source,complexity,shingles,capped,sig
             FROM funcs WHERE length(sig)=?1",
        )?;
        let rows = st.query_map(params![SIG_BYTES], |r| Ok(row_to_rec(r)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    /// candidate rows that share at least one LSH band with `fp`.
    pub fn candidates(&self, fp: &Fingerprint) -> Result<Vec<FuncRec>> {
        let mut ids = std::collections::HashSet::new();
        for (band, key) in fp.band_keys(BAND_ROWS).into_iter().enumerate() {
            let mut st = self
                .conn
                .prepare("SELECT func_id FROM bands WHERE band=?1 AND key=?2")?;
            let it = st.query_map(params![band as i64, key as i64], |r| r.get::<_, i64>(0))?;
            for id in it {
                ids.insert(id?);
            }
        }
        let mut out = Vec::new();
        for id in ids {
            let mut st = self.conn.prepare(
                "SELECT id,binary,name,entry,source,complexity,shingles,capped,sig
                 FROM funcs WHERE id=?1 AND length(sig)=?2",
            )?;
            // a band pointing at a missing or wrong-sized row (corrupt/crafted
            // db) is skipped, not a hard error that kills the whole query.
            match st
                .query_row(params![id, SIG_BYTES], |r| Ok(row_to_rec(r)))
                .optional()?
            {
                Some(rec) => out.push(rec?),
                None => continue,
            }
        }
        Ok(out)
    }
}

fn row_to_rec(r: &rusqlite::Row) -> Result<FuncRec> {
    let sig: Vec<u8> = r.get(8)?;
    let fp = Fingerprint {
        sig: decode_sig(&sig),
        shingles: r.get::<_, i64>(6)? as u32,
        complexity: r.get::<_, i64>(5)? as u32,
        capped: r.get::<_, i64>(7)? != 0,
    };
    Ok(FuncRec {
        id: r.get(0)?,
        binary: r.get(1)?,
        name: r.get(2)?,
        entry: r.get::<_, i64>(3)? as u64,
        source: r.get(4)?,
        fp,
    })
}

fn encode_sig(sig: &[u64]) -> Vec<u8> {
    let mut v = Vec::with_capacity(sig.len() * 8);
    for x in sig {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v
}

fn decode_sig(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fnprint_sig::Fingerprint;

    fn fp(seed: u64) -> Fingerprint {
        Fingerprint {
            sig: (0..SIG_LEN as u64).map(|i| i ^ seed).collect(),
            shingles: 10,
            complexity: 5,
            capped: false,
        }
    }

    #[test]
    fn roundtrip_and_candidates() {
        let db = Db::open_memory().unwrap();
        db.insert("a.bin", Some("foo"), 0x1000, "symtab", &fp(0))
            .unwrap();
        db.insert("a.bin", Some("bar"), 0x2000, "symtab", &fp(999))
            .unwrap();
        assert_eq!(db.all().unwrap().len(), 2);
        // querying with foo's own print must surface foo as a candidate
        let cands = db.candidates(&fp(0)).unwrap();
        assert!(cands.iter().any(|c| c.name.as_deref() == Some("foo")));
    }

    #[test]
    fn corrupt_sig_row_is_skipped_not_fatal() {
        let db = Db::open_memory().unwrap();
        db.insert("a.bin", Some("good"), 0x1000, "symtab", &fp(0))
            .unwrap();
        // craft a row with a wrong-sized sig blob, like a corrupt or malicious
        // corpus would have. it must be skipped, and it must not make us try to
        // decode a giant blob or blow up the query.
        db.conn
            .execute(
                "INSERT INTO funcs(binary,name,entry,source,complexity,shingles,capped,sig)
                 VALUES('evil.bin','bad',0x2000,'symtab',5,10,0,?1)",
                params![vec![0u8; 7]], // not a multiple of 8, and not SIG_BYTES
            )
            .unwrap();
        // also a plausible-but-oversized blob
        db.conn
            .execute(
                "INSERT INTO funcs(binary,name,entry,source,complexity,shingles,capped,sig)
                 VALUES('evil.bin','huge',0x3000,'symtab',5,10,0,?1)",
                params![vec![0u8; SIG_BYTES as usize * 4]],
            )
            .unwrap();

        let all = db.all().unwrap();
        assert_eq!(all.len(), 1, "only the well-formed row should load");
        assert_eq!(all[0].name.as_deref(), Some("good"));
        // candidate lookup must not error out on the corrupt rows either
        let _ = db.candidates(&fp(0)).unwrap();
    }
}
