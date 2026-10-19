"""Public byte counts. Payload contents and private inputs are never recorded.

These are application counters, not packet capture or TCP/TLS wire sizes.
"""
import re
import threading
import time

from .crypto import ProtocolError


class ApplicationMeter:
    def __init__(self):
        self.scope = 'setup'; self.events = []; self.lock = threading.Lock()

    def record(self, channel, direction, kind, size, *, scope=None, objects=None):
        if type(size) is not int or size < 0:
            raise ProtocolError('invalid byte counter')
        with self.lock:
            item = {'channel':channel, 'direction':direction, 'kind':kind,
                    'scope':self.scope if scope is None else scope, 'bytes':size}
            if objects is not None: item['objects'] = objects
            self.events.append(item)

    def report(self):
        with self.lock: events = list(self.events)
        groups = {}
        for item in events:
            key = (item['scope'], item['channel'], item['direction'])
            groups[key] = groups.get(key, 0) + item['bytes']
        return {'definition':'application payload; excludes TCP/TLS/HTTP transport headers',
                'events':events, 'totals':[{'scope':s,'channel':c,'direction':d,'bytes':n}
                    for (s,c,d),n in sorted(groups.items())]}


def graph_size(message):
    """Sum Flower deflate lengths of unique objects within ONE message graph.

    Counts Array/Record children too. No cross-message deduplication or cache
    discount; runtime-generated errors count when observed by the coordinator.
    """
    seen = set(); stack = [message]; size = 0
    while stack:
        obj = stack.pop(); identifier = obj.object_id
        if identifier in seen: continue
        seen.add(identifier); size += len(obj.deflate())
        stack.extend((obj.children or {}).values())
    return size, len(seen)


class MeteredGrid:
    """Meter the coordinator's Grid boundary without logging message contents."""
    def __init__(self, grid, meter):
        self.grid = grid; self.meter = meter; self.requests = {}; self.seen = set()

    def __getattr__(self, name): return getattr(self.grid, name)

    def push_messages(self, messages):
        messages = list(messages); ids = list(self.grid.push_messages(messages))
        for msg in messages:
            key = msg.metadata.message_id
            # Only successful accepted sends; metadata has now been populated.
            if key not in ids: continue
            size, objects = graph_size(msg)
            self.requests[key] = (self.meter.scope, msg.metadata.message_type)
            self.meter.record('flower-graph','sent',msg.metadata.message_type,size,objects=objects)
        return ids

    def pull_messages(self, ids):
        replies = list(self.grid.pull_messages(ids))
        for msg in replies:
            key = msg.metadata.message_id
            if key in self.seen: continue
            self.seen.add(key)
            scope, kind = self.requests.get(msg.metadata.reply_to_message_id,
                                            (self.meter.scope,msg.metadata.message_type))
            size, objects = graph_size(msg)
            self.meter.record('flower-graph','received',kind,size,scope=scope,objects=objects)
        return replies

    def send_and_receive(self, messages, *, timeout=None):
        ids = set(self.push_messages(messages)); replies = []
        end = None if timeout is None else time.monotonic() + timeout
        while ids and (end is None or time.monotonic() < end):
            found = self.pull_messages(ids); replies.extend(found)
            ids.difference_update(m.metadata.reply_to_message_id for m in found)
            if ids: time.sleep(getattr(self.grid,'pull_interval',.02))
        return replies


def native_partition(text, rounds):
    """Strict partition of one local tracked sent counter, checked boundaries.

    Counter follows upstream Player/ThreadQueues accounting. Startup, no_stats
    traffic, framing, TLS, retransmissions are NOT inferred from this counter.
    Round total includes any inter-boundary coordination; active is START->STOP.
    """
    expected = [('START',7),('STOP',7)] + [('START',8),('STOP',8)] * rounds
    events = []; final = []; global_counts = []; registration = False; checked = []
    for line in text.splitlines():
        if line.startswith('SEED_MPC_COMM '):
            match = re.fullmatch(r'SEED_MPC_COMM (START|STOP) (7|8) (\d+)',line)
            if not match: raise ProtocolError('malformed native byte counter')
            events.append((match[1],int(match[2]),int(match[3])))
            if len(events)>len(expected) or events[-1][:2]!=expected[len(events)-1]:
                raise ProtocolError('native counter boundary order differs')
            if len(events)>1 and events[-1][2]<events[-2][2]:
                raise ProtocolError('native byte counter decreased')
        elif line=='SEED_MPC_REG_CHECKED':
            if registration or len(events)!=2: raise ProtocolError('registration meter not CHECK bound')
            registration=True
        elif line.startswith('SEED_MPC_CHECKED '):
            match=re.fullmatch(r'SEED_MPC_CHECKED (\d+) (-?\d+) (-?\d+) (-?\d+) (-?\d+)',line)
            if not match or not registration or int(match[1])!=len(checked)+1 or len(events)!=4+2*len(checked):
                raise ProtocolError('round meter not CHECK bound')
            checked.append(int(match[1]))
        elif line.startswith('SEED_MPC_COMM_FINAL '):
            match=re.fullmatch(r'SEED_MPC_COMM_FINAL (\d+)',line)
            if not match: raise ProtocolError('malformed final counter')
            final.append(int(match[1]))
        elif line.startswith('SEED_MPC_COMM_GLOBAL '):
            match=re.fullmatch(r'SEED_MPC_COMM_GLOBAL (\d+)',line)
            if not match: raise ProtocolError('malformed global counter')
            global_counts.append(int(match[1]))
    if len(events)!=len(expected) or len(final)!=1 or len(global_counts)!=1 or len(checked)!=rounds:
        raise ProtocolError('incomplete native counters')
    if final[0]<events[-1][2]: raise ProtocolError('final counter decreased')
    rows=[]; previous=events[1][2]
    for i in range(rounds):
        start,stop=events[2+2*i][2],events[3+2*i][2]
        rows.append({'round':i+1,'start':start,'stop':stop,'sent_bytes':stop-previous,
                     'active_sent_bytes':stop-start,'between_boundary_sent_bytes':start-previous})
        previous=stop
    return {'startup_tracked_sent_bytes':events[0][2],
            'registration_sent_bytes':events[1][2]-events[0][2],
            'setup_sent_bytes':events[1][2], 'rounds':rows,
            'shutdown_sent_bytes':final[0]-previous,'total_sent_bytes':final[0],
            'global_sent_bytes':global_counts[0]}


def global_partition(parties):
    if len(parties)!=4: raise ProtocolError('four party counters required')
    total = sum(p['total_sent_bytes'] for p in parties)
    if any(p['global_sent_bytes']!=total for p in parties):
        raise ProtocolError('local and global native counters differ')
    count=len(parties[0]['rounds'])
    if any(len(p['rounds'])!=count for p in parties): raise ProtocolError('meter round counts differ')
    rows=[{'round':r+1,'sent_bytes':sum(p['rounds'][r]['sent_bytes'] for p in parties),
           'active_sent_bytes':sum(p['rounds'][r]['active_sent_bytes'] for p in parties),
           'between_boundary_sent_bytes':sum(p['rounds'][r]['between_boundary_sent_bytes'] for p in parties)}
          for r in range(count)]
    setup=sum(p['setup_sent_bytes'] for p in parties); shutdown=sum(p['shutdown_sent_bytes'] for p in parties)
    if setup+sum(r['sent_bytes'] for r in rows)+shutdown!=total:
        raise ProtocolError('native counter partition does not reconcile')
    return {'definition':'upstream tracked Player payload SENT, summed over four senders; each transmission counted once; includes live preprocessing',
            'startup_tracked_sent_bytes':sum(p['startup_tracked_sent_bytes'] for p in parties),
            'registration_sent_bytes':sum(p['registration_sent_bytes'] for p in parties),
            'setup_sent_bytes':setup,'rounds':rows,'shutdown_sent_bytes':shutdown,
            'total_sent_bytes':total,'reconciled':True,'parties':parties,
            'excluded':'untracked/no_stats setup/final exchange, native framing, TLS/TCP/IP headers/retransmissions; receive counters not measured'}
