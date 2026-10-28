import shlex
import sys
import time

import pytest
from gpt_engineer.core.default.disk_execution_env import DiskExecutionEnv


def command(program):
    return shlex.quote(sys.executable) + " -c " + shlex.quote(program)


def test_large_output_is_drained_without_deadlock(tmp_path):
    stdout, stderr, code = DiskExecutionEnv(tmp_path).run(
        command("import sys; sys.stdout.write('a'*100000); sys.stderr.write('b'*100000)"),
        timeout=5,
    )
    assert code == 0
    assert stdout == "a" * 100000
    assert stderr == "b" * 100000


def test_timeout_is_enforced_without_waiting_for_output(tmp_path):
    before = time.monotonic()
    with pytest.raises(TimeoutError):
        DiskExecutionEnv(tmp_path).run(command("import time; time.sleep(10)"), timeout=1)
    assert time.monotonic() - before < 4


def test_nonzero_exit_and_tail_output_are_retained(tmp_path):
    stdout, stderr, code = DiskExecutionEnv(tmp_path).run(
        command("import sys; print('tail'); print('diagnostic',file=sys.stderr); sys.exit(7)"),
        timeout=5,
    )
    assert (stdout, stderr, code) == ("tail\n", "diagnostic\n", 7)
