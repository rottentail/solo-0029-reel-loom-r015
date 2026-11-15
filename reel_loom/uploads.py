import hashlib
import json
import os
import threading
from .errors import LoomError, require, missing
from .values import identifier, now, text, object_body, integer, digest_hex, canonical

CHUNK_RECORD_LIMIT = 4096


class Uploads:
    """Resumable chunked media intake.

    A session pins the declared content identity (size + sha256) up front, stores
    received bytes in a dedicated scratch file, and records every accepted chunk in
    SQLite so progress survives restarts. Chunks land at explicit offsets, so a
    replayed segment overwrites the same bytes instead of duplicating them. Every
    continuation must present the pinned content digest; a different digest is a
    conflict that leaves recorded progress untouched. Only a completed session —
    coverage, digest and real probe all verified — becomes a ready asset.
    """

    def __init__(self, db, blobs, assets, settings):
        self.db, self.blobs, self.assets, self.settings = db, blobs, assets, settings
        self.guard = threading.Lock()
        self.locks = {}

    def path(self, upload_id):
        return self.blobs.scratch / ("upload-" + upload_id + ".part")

    def lock(self, upload_id):
        with self.guard:
            return self.locks.setdefault(upload_id, threading.Lock())

    def open(self, body):
        object_body(body, ("label", "size", "sha256"), ("size", "sha256"))
        label = text(body.get("label", "未命名媒体"), "label")
        size = integer(body["size"], "size", 1, self.settings.max_upload)
        sha256 = digest_hex(body["sha256"], "sha256")
        with self.db.write_unit() as db:
            row = db.execute("SELECT id FROM uploads WHERE state='open' AND size=? AND sha256=? "
                             "ORDER BY created,id LIMIT 1", (size, sha256)).fetchone()
            if row:
                return self.get(row["id"], db)
            upload_id = identifier("upload")
            db.execute("INSERT INTO uploads VALUES(?,?,?,?,?,?,?,?,?)",
                       (upload_id, label, size, sha256, "open", None, None, now(), now()))
            self.db.event(db, upload_id, "upload_opened", {"size": size, "sha256": sha256})
            return self.get(upload_id, db)

    def receive(self, upload_id, offset, content, content_digest, chunk_digest=None):
        offset = integer(offset, "offset", 0)
        require(len(content) > 0, "chunk_empty", "Chunk body is empty", 400)
        content_digest = digest_hex(content_digest, "X-Content-Digest")
        if chunk_digest is not None:
            chunk_digest = digest_hex(chunk_digest, "X-Chunk-Digest")
        with self.lock(upload_id):
            with self.db.write_unit() as db:
                session = self.get(upload_id, db)
                require(session["state"] == "open", "upload_state",
                        "Upload session is not open", 409)
                require(content_digest == session["sha256"], "upload_conflict",
                        "Continuation content differs from the session media", 409,
                        received=session["received"], declared=session["sha256"])
                require(offset + len(content) <= session["size"], "chunk_bounds",
                        "Chunk exceeds the declared media size",
                        offset=offset, length=len(content), size=session["size"])
                actual = hashlib.sha256(content).hexdigest()
                require(chunk_digest is None or chunk_digest == actual, "chunk_digest",
                        "Chunk bytes do not match the declared chunk digest", 400)
                replay = db.execute("SELECT 1 FROM upload_chunks WHERE upload=? AND position=? "
                                    "AND length=? AND digest=?",
                                    (upload_id, offset, len(content), actual)).fetchone()
                if replay:
                    return self.get(upload_id, db)
                count = db.execute("SELECT COUNT(*) n FROM upload_chunks WHERE upload=?",
                                   (upload_id,)).fetchone()["n"]
                require(count < CHUNK_RECORD_LIMIT, "chunk_count",
                        "Too many chunks for one upload session")
                self.write_chunk(upload_id, offset, content)
                db.execute("INSERT INTO upload_chunks VALUES(?,?,?,?,?)",
                           (upload_id, offset, len(content), actual, now()))
                db.execute("UPDATE uploads SET updated=? WHERE id=?", (now(), upload_id))
                self.db.event(db, upload_id, "chunk_received",
                              {"position": offset, "length": len(content)})
                return self.get(upload_id, db)

    def write_chunk(self, upload_id, offset, content):
        path = self.path(upload_id)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            view = memoryview(content)
            written = 0
            while written < len(content):
                written += os.pwrite(fd, view[written:], offset + written)
            os.fsync(fd)
        finally:
            os.close(fd)

    def complete(self, upload_id):
        with self.lock(upload_id):
            with self.db.read() as db:
                session = self.get(upload_id, db)
            if session["state"] == "completed":
                return self.assets.get(session["asset"])
            require(session["state"] == "open", "upload_state",
                    "Upload session is not open", 409)
            require(session["received"] == session["size"], "upload_incomplete",
                    "Upload is missing byte ranges", 409,
                    received=session["received"], size=session["size"])
            path = self.path(upload_id)
            hasher = hashlib.sha256()
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024*1024), b""):
                    hasher.update(chunk)
            require(hasher.hexdigest() == session["sha256"], "upload_mismatch",
                    "Assembled media differs from the declared content digest", 409,
                    received=session["received"])
            try:
                asset = self.assets.ingest_file(path, session["label"])
            except LoomError as exc:
                # The digest pins the bytes, so undecodable content can never
                # become a usable source; release the scratch space it held.
                self.terminate(upload_id, exc.as_dict())
                raise
            with self.db.write_unit() as db:
                db.execute("UPDATE uploads SET state='completed',asset=?,updated=? WHERE id=?",
                           (asset["id"], now(), upload_id))
                self.db.event(db, upload_id, "completed",
                              {"asset": asset["id"], "blob": asset["blob"]})
            path.unlink(missing_ok=True)
            return asset

    def abort(self, upload_id):
        with self.lock(upload_id):
            with self.db.write_unit() as db:
                session = self.get(upload_id, db)
                require(session["state"] != "completed", "upload_state",
                        "Completed uploads cannot be aborted", 409)
                if session["state"] == "open":
                    db.execute("UPDATE uploads SET state='aborted',updated=? WHERE id=?",
                               (now(), upload_id))
                    self.db.event(db, upload_id, "aborted", {})
            self.path(upload_id).unlink(missing_ok=True)
            return self.get(upload_id)

    def terminate(self, upload_id, error):
        with self.db.write_unit() as db:
            db.execute("UPDATE uploads SET state='aborted',error=?,updated=? WHERE id=?",
                       (canonical(error), now(), upload_id))
            self.db.event(db, upload_id, "aborted", {"error": error})
        self.path(upload_id).unlink(missing_ok=True)

    def get(self, upload_id, db=None):
        if db is None:
            with self.db.read() as read:
                return self.get(upload_id, read)
        row = db.execute("SELECT * FROM uploads WHERE id=?", (upload_id,)).fetchone()
        if row is None:
            raise missing("upload", upload_id)
        chunks = db.execute("SELECT position,length FROM upload_chunks WHERE upload=? "
                            "ORDER BY position,length", (upload_id,)).fetchall()
        ranges = merge_ranges([(chunk["position"], chunk["position"]+chunk["length"])
                               for chunk in chunks])
        result = {**dict(row), "received": sum(b-a for a, b in ranges),
                  "ranges": [[a, b] for a, b in ranges]}
        result["error"] = json.loads(result["error"]) if result["error"] else None
        return result

    def list(self, state=None, limit=100):
        with self.db.read() as db:
            if state:
                rows = db.execute("SELECT id FROM uploads WHERE state=? ORDER BY created DESC,id LIMIT ?",
                                  (state, limit)).fetchall()
            else:
                rows = db.execute("SELECT id FROM uploads ORDER BY created DESC,id LIMIT ?",
                                  (limit,)).fetchall()
            return [self.get(row["id"], db) for row in rows]

    def summary(self):
        with self.db.read() as db:
            rows = db.execute("SELECT state,COUNT(*) n FROM uploads GROUP BY state").fetchall()
            states = {row["state"]: row["n"] for row in rows}
            return {"open": states.get("open", 0), "completed": states.get("completed", 0),
                    "aborted": states.get("aborted", 0)}

    def recover(self):
        """Reconcile scratch files with persisted sessions after a restart.

        Open sessions keep their scratch so producers can continue; a session whose
        scratch vanished drops its chunk records instead of claiming bytes that do
        not exist; scratch without an open session is removed so terminated intake
        never holds unexplained space.
        """
        with self.db.write_unit() as db:
            open_ids = {row["id"] for row in db.execute("SELECT id FROM uploads WHERE state='open'")}
            resets = []
            for upload_id in sorted(open_ids):
                if not self.path(upload_id).is_file():
                    db.execute("DELETE FROM upload_chunks WHERE upload=?", (upload_id,))
                    self.db.event(db, upload_id, "progress_reset", {"reason": "scratch_missing"})
                    resets.append(upload_id)
        removed_bytes = 0
        for part in sorted(self.blobs.scratch.glob("upload-*.part")):
            upload_id = part.name[len("upload-"):-len(".part")]
            if upload_id not in open_ids:
                removed_bytes += part.stat().st_size
                part.unlink(missing_ok=True)
        return {"open_sessions": len(open_ids), "progress_resets": resets,
                "orphan_bytes_removed": removed_bytes}


def merge_ranges(spans):
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged
