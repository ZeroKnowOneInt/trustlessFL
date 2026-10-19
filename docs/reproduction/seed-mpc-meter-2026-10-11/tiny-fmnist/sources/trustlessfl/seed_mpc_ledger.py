"""Durable one-proposal locks and exactly-once public model transitions.

Stores public transcripts only, never AES keys or MPC shares. Safety assumes
honest disks are durable and not rolled back. Lost state requires a new session.
"""
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3

from .crypto import ProtocolError, canonical, digest


class SeedLedger:
    def __init__(self,path,contract,model,*,create=False):
        path=Path(path)
        if not path.exists() and not create:
            raise ProtocolError('ledger missing: start a fresh session')
        if create: path.parent.mkdir(parents=True,exist_ok=True)
        self.db=sqlite3.connect(path,timeout=10,isolation_level=None)
        self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY, fingerprint TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS head (id INTEGER PRIMARY KEY, round INTEGER, decision TEXT, model TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS rounds (round INTEGER PRIMARY KEY, input_hash TEXT, manifest TEXT, phase TEXT, input_vote TEXT, result_body TEXT, result_vote TEXT, certificate TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS collections (round INTEGER PRIMARY KEY, collection_hash TEXT UNIQUE, body TEXT, deadline_ms INTEGER, phase TEXT, input_hash TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS submissions (round INTEGER, client TEXT, submission_hash TEXT, payload TEXT, receipt TEXT, PRIMARY KEY(round,client))')
        self.db.execute('CREATE TABLE IF NOT EXISTS collection_proofs (round INTEGER PRIMARY KEY, certificates TEXT)')
        with self.transaction() as db:
            row=db.execute('SELECT fingerprint FROM meta WHERE id=1').fetchone()
            if row is None:
                if not create: raise ProtocolError('uninitialized ledger')
                db.execute('INSERT INTO meta VALUES (1,?)',(digest(contract),))
                db.execute('INSERT INTO head VALUES (1,0,?,?)',(digest({'genesis':contract}),canonical(model).decode()))
            elif row['fingerprint']!=digest(contract):
                raise ProtocolError('ledger session/identity contract differs')

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield self.db
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def close(self): self.db.close()

    def head(self):
        row=self.db.execute('SELECT * FROM head WHERE id=1').fetchone()
        return {'round':row['round'],'decision':row['decision'],'model':json.loads(row['model'])}

    def row(self,round_id):
        row=self.db.execute('SELECT * FROM rounds WHERE round=?',(round_id,)).fetchone()
        return dict(row) if row else None

    @staticmethod
    def _now(clock):
        now=clock()
        if type(now) is not int or not 0<=now<2**63: raise ProtocolError('invalid local collection clock')
        return now

    def collection(self,collection_hash):
        row=self.db.execute('SELECT * FROM collections WHERE collection_hash=?',(collection_hash,)).fetchone()
        return dict(row) if row else None

    def open_collection(self,body,window_ms,clock,genesis):
        round_id=body['context']['round_id']; collection_hash=digest(body)
        with self.transaction() as db:
            row=db.execute('SELECT * FROM collections WHERE round=?',(round_id,)).fetchone()
            if row:
                if row['collection_hash']!=collection_hash: raise ProtocolError('conflicting collection context')
                return dict(row)
            head=self.head()
            parent=genesis if head['round']==0 else head['decision']
            if (round_id!=head['round']+1 or body['parent_decision']!=parent
                    or body['context']['model_hash']!=digest(head['model']) or self.row(round_id)):
                raise ProtocolError('collection differs from current head')
            deadline=self._now(clock)+window_ms
            if deadline>=2**63: raise ProtocolError('collection deadline overflow')
            db.execute('INSERT INTO collections VALUES (?,?,?,?,\'open\',NULL)',
                       (round_id,collection_hash,canonical(body).decode(),deadline))
        return self.collection(collection_hash)

    def store_submission(self,round_id,collection_hash,client,payload,receipt,clock):
        submission_hash=digest(payload)
        with self.transaction() as db:
            collection=self.collection(collection_hash)
            if not collection or collection['round']!=round_id: raise ProtocolError('collection not opened')
            old=db.execute('SELECT * FROM submissions WHERE round=? AND client=?',(round_id,client)).fetchone()
            if old:
                if old['submission_hash']!=submission_hash: raise ProtocolError('conflicting client submission')
                # Query/retry returns a previously committed signature, never a new late receipt.
                return json.loads(old['receipt'])
            if (collection['phase']!='open' or self._now(clock)>=collection['deadline_ms']
                    or self.row(round_id) or round_id!=self.head()['round']+1):
                raise ProtocolError('collection closed or expired')
            db.execute('INSERT INTO submissions VALUES (?,?,?,?,?)',
                       (round_id,client,submission_hash,canonical(payload).decode(),canonical(receipt).decode()))
        return receipt

    def submission(self,collection_hash,client):
        collection=self.collection(collection_hash)
        if not collection: raise ProtocolError('unknown collection')
        row=self.db.execute('SELECT payload,receipt FROM submissions WHERE round=? AND client=?',
                            (collection['round'],client)).fetchone()
        return None if row is None else {'submission':json.loads(row['payload']),'receipt':json.loads(row['receipt'])}

    def prepare(self,round_id,input_hash,manifest,vote,*,collection_hash=None,submissions=None,clock=None,proofs=None):
        with self.transaction() as db:
            head=self.head()
            if round_id!=head['round']+1: raise ProtocolError('stale or skipped input round')
            row=self.row(round_id)
            if row:
                if row['input_hash']!=input_hash: raise ProtocolError('round already locked to another input')
                return json.loads(row['input_vote'])
            if collection_hash is not None:
                collection=self.collection(collection_hash)
                if (not collection or collection['round']!=round_id or collection['phase']!='open'
                        or not isinstance(submissions,dict)):
                    raise ProtocolError('collection not open for snapshot')
                rows=db.execute('SELECT client,submission_hash FROM submissions WHERE round=?',(round_id,)).fetchall()
                if any(submissions.get(r['client'])!=r['submission_hash'] for r in rows):
                    raise ProtocolError('snapshot omits or replaces receipted input')
                # A complete registered roster may close early; a subset must await the local deadline.
                if self._now(clock)<collection['deadline_ms'] and not all(manifest['presence']):
                    raise ProtocolError('collection window still open')
                db.execute('UPDATE collections SET phase=\'closed\',input_hash=? WHERE round=?',
                           (input_hash,round_id))
                db.execute('INSERT INTO collection_proofs VALUES (?,?)',(round_id,canonical(proofs).decode()))
            db.execute('INSERT INTO rounds VALUES (?,?,?,\'prepared\',?,NULL,NULL,NULL)',
                       (round_id,input_hash,canonical(manifest).decode(),canonical(vote).decode()))
        # No signature is returned before its lock is committed.
        return vote

    def reserve(self,round_id,input_hash):
        with self.transaction() as db:
            row=self.row(round_id)
            if not row or row['input_hash']!=input_hash or row['phase']!='prepared':
                raise ProtocolError('execution consumed or input not prepared')
            db.execute('UPDATE rounds SET phase=\'running\' WHERE round=?',(round_id,))

    def checked(self,round_id,input_hash,body,vote):
        with self.transaction() as db:
            row=self.row(round_id)
            if not row or row['input_hash']!=input_hash: raise ProtocolError('unreserved result')
            if row['phase']=='checked' and json.loads(row['result_body'])==body:
                return json.loads(row['result_vote'])
            if row['phase']!='running': raise ProtocolError('result already consumed')
            db.execute('UPDATE rounds SET phase=\'checked\',result_body=?,result_vote=? WHERE round=?',
                       (canonical(body).decode(),canonical(vote).decode(),round_id))
        return vote

    def decide(self,round_id,input_hash,body,certificate,model):
        with self.transaction() as db:
            row=self.row(round_id)
            if not row or row['input_hash']!=input_hash: raise ProtocolError('decision input not prepared')
            if row['phase']=='decided':
                if json.loads(row['result_body'])!=body: raise ProtocolError('conflicting decided result')
                return False
            if round_id!=self.head()['round']+1: raise ProtocolError('stale or skipped result round')
            if row['result_body'] is not None and json.loads(row['result_body'])!=body:
                raise ProtocolError('certificate differs from local checked result')
            db.execute('UPDATE rounds SET phase=\'decided\',result_body=?,certificate=? WHERE round=?',
                       (canonical(body).decode(),canonical(certificate).decode(),round_id))
            # Decision BODY hash is invariant under different valid QC subsets.
            db.execute('UPDATE head SET round=?,decision=?,model=? WHERE id=1',
                       (round_id,digest(body),canonical(model).decode()))
        return True
