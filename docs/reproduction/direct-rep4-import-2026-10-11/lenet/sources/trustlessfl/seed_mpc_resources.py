"""Public Linux GNU time resource counters, separate from protocol evidence."""
from pathlib import Path

from .crypto import ProtocolError


def read_resources(path):
    fields={}
    for line in Path(path).read_text().splitlines():
        if ': ' in line:
            key,value=line.strip().rsplit(': ',1); fields[key]=value
    try:
        result={'peak_rss_kib':int(fields['Maximum resident set size (kbytes)']),
                'user_cpu_seconds':float(fields['User time (seconds)']),
                'system_cpu_seconds':float(fields['System time (seconds)']),
                'exit_status':int(fields['Exit status'])}
    except (KeyError,ValueError) as exc:
        raise ProtocolError('incomplete native resource report') from exc
    if result['exit_status']!=0 or any(v<0 for v in result.values()):
        raise ProtocolError('native resource report indicates failure')
    return result
