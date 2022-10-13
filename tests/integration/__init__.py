import subprocess
from types import SimpleNamespace


def shellexec(command: str):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
    output = result.stdout.split('\n')
    error = result.stderr.split('\n')
    returncode = result.returncode

    return SimpleNamespace(stdout=output, stderr=error, returncode=returncode)
