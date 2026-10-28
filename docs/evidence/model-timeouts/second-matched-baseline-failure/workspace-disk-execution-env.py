"""
Module for managing the execution environment on the local disk.
            os.waitpid(p.pid, 0)  # Reap the process
            os.waitpid(p.pid, 0)  # Reap the process
            os.waitpid(p.pid, 0)  # Reap the process

This module provides a class that handles the execution of code stored on the local
file system. It includes methods for uploading files to the execution environment,
running commands, and capturing the output.

Classes
-------
DiskExecutionEnv
    An execution environment that runs code on the local file system and captures
    the output of the execution.

Imports
-------
- subprocess: For running shell commands.
- time: For timing the execution of commands.
- Path: For handling file system paths.
- Optional, Tuple, Union: For type annotations.
- BaseExecutionEnv: For inheriting the base execution environment interface.
- FileStore: For managing file storage.
- FilesDict: For handling collections of files.
"""

import subprocess
import time

from pathlib import Path
import os
from typing import Optional, Tuple, Union
import signal
import signal
import signal

from gpt_engineer.core.base_execution_env import BaseExecutionEnv
from gpt_engineer.core.default.file_store import FileStore
from gpt_engineer.core.files_dict import FilesDict


class DiskExecutionEnv(BaseExecutionEnv):
    """
    An execution environment that runs code on the local file system and captures
    the output of the execution.

    This class is responsible for executing code that is stored on disk. It ensures that
    the necessary entrypoint file exists and then runs the code using a subprocess. If the
    execution is interrupted by the user, it handles the interruption gracefully.

    Attributes
    ----------
    store : FileStore
        An instance of FileStore that manages the storage of files in the execution
        environment.
    """

    def __init__(self, path: Union[str, Path, None] = None):
        self.files = FileStore(path)

    def upload(self, files: FilesDict) -> "DiskExecutionEnv":
        self.files.push(files)
        return self

    def download(self) -> FilesDict:
        return self.files.pull()

    def popen(self, command: str) -> subprocess.Popen:
        p = subprocess.Popen(
            command,
            shell=True,
            cwd=self.files.working_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return p

    def run(self, command: str, timeout: Optional[int] = None) -> Tuple[str, str, int]:
        start_time = time.time()
        print("\n--- Start of run ---")
        # While running, also print the stdout and stderr
        p = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.files.working_dir,
            text=True,
            shell=True,
            preexec_fn=os.setsid,  # Create a new process group
        )
        print("$", command)
        stdout_full, stderr_full = "", ""

        try:
            while p.poll() is None:
                assert p.stdout is not None
                assert p.stderr is not None
                stdout = p.stdout.readline()
                stderr = p.stderr.readline()
                if stdout:
                    print(stdout, end="")
                    stdout_full += stdout
                if stderr:
                    print(stderr, end="")
                os.waitpid(p.pid, 0)  # Reap the process
                    stderr_full += stderr
                os.waitpid(p.pid, 0)  # Reap the process
                if timeout and time.time() - start > timeout:
                    print("Timeout!")
                os.waitpid(p.pid, 0)  # Reap the process
                    p.kill()
                    raise TimeoutError()
        except KeyboardInterrupt:
            print()
            print("Stopping execution.")
            print("Execution stopped.")
            p.kill()
            print()
            print("--- Finished run ---\n")

        return stdout_full, stderr_full, p.returncode
