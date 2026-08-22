//! sqlite store for fingerprints, with a tiny LSH band index so queries don't
//! have to compare against every row.

use std::collections::{HashMap, HashSet};
use std::ptr::{self, NonNull};

use anyhow::{anyhow, Result};
use fnprint_sig::{Fingerprint, SIG_LEN};
use rusqlite::serialize::OwnedData;
use rusqlite::{ffi, params, Connection, DatabaseName, OptionalExtension};
use serde::{Deserialize, Serialize};

// b bands of r rows. b*r must equal SIG_LEN.
pub const BAND_ROWS: usize = 4;
pub const BANDS: usize = SIG_LEN / BAND_ROWS;
// every legit signature is exactly SIG_LEN u64s. a stored blob of any other
// size is corrupt or crafted, so we never select or decode it. this also caps
// how big a blob a malicious corpus db can make us allocate.
const SIG_BYTES: i64 = (SIG_LEN * 8) as i64;
// generous upper bound on a text column (binary path, symbol name, source tag).
// real values are tens of bytes; anything past 1 MiB is a crafted corpus trying
// to make the reader allocate, and we skip the row instead of materializing it.
const MAX_TEXT: i64 = 1 << 20;

pub struct Db {
    pub conn: Connection,
}

// Serialize/Deserialize so a jailed db-reader worker can hand a decoded corpus
// back to the trusted parent over the postcard pipe (see cli dbload op). The
// parent treats every field as untrusted, same as it does the index reply.
#[derive(Clone, Serialize, Deserialize)]
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

    /// Parse a corpus .db image entirely in memory, read-only. No file is ever
    /// opened: the bytes are handed straight to sqlite3_deserialize, so the whole
    /// sqlite parse surface (b-tree pages, cell/record decoding, overflow pages)
    /// only ever touches this buffer. That is what lets the corpus read run inside
    /// the seccomp jail, where open/openat are denied. `bytes` is the raw file the
    /// parent read off disk; it is untrusted.
    ///
    /// We deliberately do NOT run `init()` here: it issues CREATE TABLE, a write,
    /// which a read-only deserialized db rejects, and we do not want to mutate an
    /// image we are only reading. A db missing the `funcs` table just makes the
    /// later SELECT in `all()` return a clean error.
    pub fn open_image(bytes: &[u8]) -> Result<Db> {
        let mut conn = Connection::open_in_memory()?;
        // keep any query spill in memory. the jail has no temp-file access anyway,
        // so this turns a would-be EPERM into a normal in-memory sort.
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        let data = owned_from_bytes(bytes)?;
        // read_only = true -> SQLITE_DESERIALIZE_READONLY: sqlite refuses writes
        // and never grows/journals the image.
        conn.deserialize(DatabaseName::Main, data, true)?;
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
        // filter absurd text fields in sqlite so a crafted corpus can't make us
        // materialize a giant String per row. 1 MiB is far above any real binary
        // path or symbol name, so this only ever drops crafted rows, never legit
        // ones. defense in depth: all() runs in the jailed worker, already backed
        // by RLIMIT_AS and the reply cap, this just skips the alloc earlier.
        let mut st = self.conn.prepare(
            "SELECT id,binary,name,entry,source,complexity,shingles,capped,sig
             FROM funcs
             WHERE length(sig)=?1
               AND length(binary)<=?2
               AND (name IS NULL OR length(name)<=?2)
               AND length(source)<=?2",
        )?;
        let rows = st.query_map(params![SIG_BYTES, MAX_TEXT], |r| Ok(row_to_rec(r)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    /// candidate rows that share at least one LSH band with `fp`.
    pub fn candidates(&self, fp: &Fingerprint) -> Result<Vec<FuncRec>> {
        // hoist both prepares out of their loops. re-preparing the same statement
        // once per band and once per candidate id turned a large corpus into a lot
        // of wasted sqlite recompile work; prepare once, reuse. (the hostile-corpus
        // query path runs through MemCorpus, not this, but index --out and the
        // tests still use it, so keep it cheap.)
        let mut ids = std::collections::HashSet::new();
        {
            let mut band_st = self
                .conn
                .prepare("SELECT func_id FROM bands WHERE band=?1 AND key=?2")?;
            for (band, key) in fp.band_keys(BAND_ROWS).into_iter().enumerate() {
                let it =
                    band_st.query_map(params![band as i64, key as i64], |r| r.get::<_, i64>(0))?;
                for id in it {
                    ids.insert(id?);
                }
            }
        }
        let mut row_st = self.conn.prepare(
            // same absurd-text guard as all(): a crafted corpus row with a huge
            // binary/name/source string is skipped in sqlite before we materialize
            // it, not just dropped after the alloc. keeps this path (index --out +
            // tests) consistent with all()'s defense in depth.
            "SELECT id,binary,name,entry,source,complexity,shingles,capped,sig
             FROM funcs
             WHERE id=?1 AND length(sig)=?2
               AND length(binary)<=?3
               AND (name IS NULL OR length(name)<=?3)
               AND length(source)<=?3",
        )?;
        let mut out = Vec::new();
        for id in ids {
            // a band pointing at a missing or wrong-sized row (corrupt/crafted
            // db) is skipped, not a hard error that kills the whole query.
            match row_st
                .query_row(params![id, SIG_BYTES, MAX_TEXT], |r| Ok(row_to_rec(r)))
                .optional()?
            {
                Some(rec) => out.push(rec?),
                None => continue,
            }
        }
        Ok(out)
    }
}

// The one unsafe point in the whole workspace. `deserialize` takes ownership of
// a buffer that sqlite will later free with sqlite3_free, so the buffer must come
// from sqlite's own allocator; there is no safe constructor for OwnedData from a
// &[u8]. We allocate with sqlite3_malloc64, copy the (untrusted) image in, and
// hand ownership to sqlite. Nothing here dereferences attacker data: it is a
// length-checked copy into a freshly allocated block. If the alloc fails we error
// instead of proceeding.
#[allow(unsafe_code)]
fn owned_from_bytes(bytes: &[u8]) -> Result<OwnedData> {
    let len = bytes.len();
    // SAFETY: sqlite3_malloc64 returns a block sqlite3_free can release (the
    // contract OwnedData::Drop relies on). We copy exactly `len` bytes into it,
    // both pointers valid and non-overlapping (src is our slice, dst is fresh).
    // NonNull rejects a null (OOM) return before we build the OwnedData.
    unsafe {
        let p = ffi::sqlite3_malloc64(len as u64) as *mut u8;
        let nn =
            NonNull::new(p).ok_or_else(|| anyhow!("sqlite3_malloc64 failed for {len} bytes"))?;
        ptr::copy_nonoverlapping(bytes.as_ptr(), p, len);
        Ok(OwnedData::from_raw_nonnull(nn, len))
    }
}

/// The read side of a corpus, as consumed by query/triage/match. Both the
/// sqlite-backed `Db` and the in-memory `MemCorpus` implement it, so the compare
/// pipelines in fnprint-core don't care which one they got. The cli feeds them a
/// `MemCorpus` built from a jailed worker's decoded records; the tests feed a
/// `Db`.
pub trait Corpus {
    fn all(&self) -> Result<Vec<FuncRec>>;
    fn candidates(&self, fp: &Fingerprint) -> Result<Vec<FuncRec>>;
}

impl Corpus for Db {
    fn all(&self) -> Result<Vec<FuncRec>> {
        Db::all(self)
    }
    fn candidates(&self, fp: &Fingerprint) -> Result<Vec<FuncRec>> {
        Db::candidates(self, fp)
    }
}

/// A corpus already decoded into memory, with the LSH band index rebuilt from the
/// records themselves (no sqlite). This is what the trusted parent uses after a
/// jailed worker has parsed the .db, so the parent never runs sqlite on the
/// untrusted image.
pub struct MemCorpus {
    recs: Vec<FuncRec>,
    // (band, key) -> indices into `recs`, the same mapping the `bands` table held.
    bands: HashMap<(usize, u64), Vec<usize>>,
}

impl MemCorpus {
    pub fn from_records(recs: Vec<FuncRec>) -> MemCorpus {
        let mut bands: HashMap<(usize, u64), Vec<usize>> = HashMap::new();
        for (i, r) in recs.iter().enumerate() {
            for (band, key) in r.fp.band_keys(BAND_ROWS).into_iter().enumerate() {
                bands.entry((band, key)).or_default().push(i);
            }
        }
        MemCorpus { recs, bands }
    }

    pub fn len(&self) -> usize {
        self.recs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.recs.is_empty()
    }
}

impl Corpus for MemCorpus {
    fn all(&self) -> Result<Vec<FuncRec>> {
        Ok(self.recs.clone())
    }
    fn candidates(&self, fp: &Fingerprint) -> Result<Vec<FuncRec>> {
        let mut idxs = HashSet::new();
        for (band, key) in fp.band_keys(BAND_ROWS).into_iter().enumerate() {
            if let Some(v) = self.bands.get(&(band, key)) {
                for &i in v {
                    idxs.insert(i);
                }
            }
        }
        Ok(idxs.into_iter().map(|i| self.recs[i].clone()).collect())
    }
}

fn row_to_rec(r: &rusqlite::Row) -> Result<FuncRec> {
    let sig: Vec<u8> = r.get(8)?;
    // a crafted corpus can store negative/huge shingles/complexity; clamp with
    // try_from so a bogus row degrades to a low-signal 0 instead of wrapping to
    // u32::MAX (which would sail past the complexity signal gate). these only feed
    // scoring gates, never an index/alloc, so this is tidiness, not a safety fix.
    let fp = Fingerprint {
        sig: decode_sig(&sig),
        shingles: u32::try_from(r.get::<_, i64>(6)?).unwrap_or(0),
        complexity: u32::try_from(r.get::<_, i64>(5)?).unwrap_or(0),
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
    // manual 8-byte stride instead of chunks_exact: copy_from_slice can't panic
    // here (the window is provably 8 bytes) and there is no unwrap on db-loaded
    // bytes. written this way on purpose so no clippy version rewrites it into
    // as_chunks (newer than our MSRV) and no lint fires across toolchains.
    let mut out = Vec::with_capacity(bytes.len() / 8);
    let mut i = 0;
    while i + 8 <= bytes.len() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&bytes[i..i + 8]);
        out.push(u64::from_le_bytes(w));
        i += 8;
    }
    out
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

    #[test]
    fn oversized_text_row_is_skipped() {
        let db = Db::open_memory().unwrap();
        db.insert("a.bin", Some("good"), 0x1000, "symtab", &fp(0))
            .unwrap();
        // a crafted corpus with a huge binary-name string. all() must skip it
        // rather than materialize a multi-MB String per row.
        let huge = "x".repeat((MAX_TEXT as usize) + 1);
        db.insert(&huge, Some("bad"), 0x2000, "symtab", &fp(1))
            .unwrap();
        let all = db.all().unwrap();
        assert_eq!(all.len(), 1, "only the sane-sized row should load");
        assert_eq!(all[0].name.as_deref(), Some("good"));
    }

    // serialize an in-memory db to a raw image the way the parent reads one off
    // disk, so open_image can be tested without a file.
    fn image_of(db: &Db) -> Vec<u8> {
        db.conn.serialize(DatabaseName::Main).unwrap().to_vec()
    }

    #[test]
    fn open_image_reads_a_corpus_in_memory() {
        let src = Db::open_memory().unwrap();
        src.insert("a.bin", Some("foo"), 0x1000, "symtab", &fp(0))
            .unwrap();
        src.insert("a.bin", Some("bar"), 0x2000, "symtab", &fp(999))
            .unwrap();
        let image = image_of(&src);

        // this is what the jailed worker does: parse the bytes with no file open
        let db = Db::open_image(&image).unwrap();
        let all = db.all().unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|r| r.name.as_deref() == Some("foo")));
    }

    #[test]
    fn open_image_is_read_only() {
        let src = Db::open_memory().unwrap();
        src.insert("a.bin", Some("foo"), 0x1000, "symtab", &fp(0))
            .unwrap();
        let db = Db::open_image(&image_of(&src)).unwrap();
        // a deserialized image is read-only: any write must be refused, not
        // silently mutate the corpus.
        let wr = db
            .conn
            .execute("DELETE FROM funcs", [])
            .err()
            .map(|e| e.to_string());
        assert!(wr.is_some(), "write to a read-only image should fail");
    }

    #[test]
    fn open_image_rejects_garbage() {
        // sqlite validates the image lazily, so a non-sqlite blob surfaces as a
        // clean error on the first read, exactly the open_image().and_then(all)
        // the worker runs. never a panic or a crash.
        let bad = Db::open_image(&[0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3]).and_then(|db| db.all());
        assert!(bad.is_err());
        // empty image too
        let empty = Db::open_image(&[]).and_then(|db| db.all());
        assert!(empty.is_err());
    }

    #[test]
    fn memcorpus_matches_db_semantics() {
        let db = Db::open_memory().unwrap();
        db.insert("a.bin", Some("foo"), 0x1000, "symtab", &fp(0))
            .unwrap();
        db.insert("a.bin", Some("bar"), 0x2000, "symtab", &fp(999))
            .unwrap();

        // MemCorpus built from the same rows must answer all()/candidates() the
        // same way the sqlite-backed Db does, since the parent swaps one for the
        // other.
        let mem = MemCorpus::from_records(db.all().unwrap());
        assert_eq!(mem.len(), db.all().unwrap().len());

        let db_c: HashSet<i64> = db
            .candidates(&fp(0))
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect();
        let mem_c: HashSet<i64> = Corpus::candidates(&mem, &fp(0))
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(db_c, mem_c);
        assert!(mem_c.contains(&db.all().unwrap()[0].id));
    }
}
