"""Pinned, process-local repair of Flower's synchronous Ray submission failure.

No installed dependency is edited. Only a failure before remote submission
returns a future can be retried; completed or uncertain training is not replayed.
"""
import hashlib
import importlib.metadata
import inspect
import sys
import threading
import time

SUBMIT_SHA256 = '672402921baad47352ebe3133ebd90248314959ce3836f08b6c8723111ec17c9'
_LOCK = threading.RLock()


def _before_remote_submission(error):
    if str(error) != 'dictionary changed size during iteration':
        return False
    traceback = error.__traceback__
    while traceback is not None:
        code = traceback.tb_frame.f_code
        if (code.co_name == '_serialize_to_pickle5'
                and code.co_filename.replace('\\', '/').endswith('/ray/_private/serialization.py')):
            return True
        traceback = traceback.tb_next
    return False


def guarded_submit(self, actor_fn, job):
    """Restore the reserved actor on every synchronous submission exception."""
    with _LOCK:
        app_fn, message, cid, context = job
        actor = self.pool.pop()
        try:
            for attempt in range(3):
                try:
                    future = actor_fn(actor, app_fn, message, cid, context)
                    break
                except RuntimeError as error:
                    # Ray's observed prepare_args/cloudpickle exception occurs
                    # before submit_actor_task enqueues the remote invocation.
                    # Never retry transport, actor, client or arbitrary failures.
                    if not _before_remote_submission(error) or attempt == 2:
                        raise
                    print(f'SEED_MPC_RUNTIME_SUBMIT_RETRY attempt={attempt + 1}',
                          file=sys.stderr, flush=True)
                    time.sleep(.02)
        except BaseException:
            self.pool.append(actor)
            raise
        self._future_to_actor[future] = actor
        return future


def install():
    """Fail closed if the dependency implementation differs from the reviewed one."""
    from flwr.simulation.ray_transport.ray_actor import BasicActorPool
    if BasicActorPool.submit is guarded_submit:
        return
    if (importlib.metadata.version('flwr') != '1.36.0'
            or importlib.metadata.version('ray') != '2.55.1'):
        raise RuntimeError('seed-MPC runtime guard dependency version differs')
    original = hashlib.sha256(inspect.getsource(BasicActorPool.submit).encode()).hexdigest()
    if original != SUBMIT_SHA256:
        raise RuntimeError('seed-MPC runtime guard source differs')
    BasicActorPool.submit = guarded_submit


def learning_workload_completed(checks, client_count):
    """All-present learning benchmarks require successful updates every round."""
    return bool(checks) and all(
        row['presence'] == [1] * client_count and row['status'] == 'ok'
        for row in checks)
