"""Large legitimate rosters get bounded transport capacity, not unlimited RPC."""
from trustlessfl.seed_mpc_service import request_size_limit
from trustlessfl.seed_mpc_policy import SeedMPCPolicy


def test_request_budget_covers_full_large_manifest_and_has_a_hard_ceiling():
    small=SeedMPCPolicy(53,4,20000,2500000000)
    original=SeedMPCPolicy(61706,4,20000,2500000000)
    large=SeedMPCPolicy(61706,100,20000,2500000000)
    enormous=SeedMPCPolicy(61706,1000,20000,2500000000)
    assert request_size_limit(small)==request_size_limit(original)==16*1024*1024
    assert 150_000_000<request_size_limit(large)<512*1024*1024
    assert request_size_limit(enormous)==512*1024*1024


def test_pipe_stream_preserves_all_private_words_under_partial_writes(monkeypatch):
    from trustlessfl import seed_mpc_service as service
    output=bytearray();chunks=[]
    values=[(-1 if i%2 else 1)*(2**63+i) for i in range(10003)]
    def write(fd,buffer):
        assert fd==123
        chunks.append(len(buffer));n=min(37,len(buffer));output.extend(buffer[:n]);return n
    monkeypatch.setattr(service.os,'write',write)
    monkeypatch.setattr(service.select,'select',lambda *args:([],[123],[]))
    service.pipe_write(123,(v for v in values),30)
    assert bytes(output)==('\n'.join(map(str,values))+'\n').encode()
    assert max(chunks)<100000  # one bounded conversion batch, no whole-round string
