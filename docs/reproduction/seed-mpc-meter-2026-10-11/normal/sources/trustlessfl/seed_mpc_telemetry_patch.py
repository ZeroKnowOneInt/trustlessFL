"""Observer-only patch; no protocol, checking, or network operation is changed."""
PATCH_ID = 'base-machine-public-sent-counter-v1'
APPROVED_BUILD_SHA256 = '7af95c645bdfec6f24f2df71c51ebf9e399477737355e809dba7b09549886909'


def patched_source(source):
    replacements = (
        ('  timer[n].start(total_stats());',
         '  cout << "SEED_MPC_COMM START " << n << " " << total_stats().comm_stats.sent << endl;\n'
         '  timer[n].start(total_stats());'),
        ('  timer[n].stop(total_stats());',
         '  timer[n].stop(total_stats());\n'
         '  cout << "SEED_MPC_COMM STOP " << n << " " << total_stats().comm_stats.sent << endl;'),
        ('  cerr << "Global data sent = "',
         '  cerr << "SEED_MPC_COMM_FINAL " << stats.sent << endl;\n'
         '  cerr << "SEED_MPC_COMM_GLOBAL " << global << endl;\n'
         '  cerr << "Global data sent = "'),
    )
    for before, after in replacements:
        if source.count(before) != 1:
            raise ValueError('observer patch source anchor differs')
        source = source.replace(before, after)
    return source
