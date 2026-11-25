"""Run the signed workers against synthetic sessions, under a temporary HOME."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile

doctl = Path(sys.argv[1]).resolve()
deny = {"ok": False, "error": "fixture approval denied"}
token = "synthetic-access-token"
session = json.dumps({"access_token": token})


def check(worker, args, requests, success, expected):
    with tempfile.TemporaryDirectory() as home, tempfile.TemporaryFile() as log:
        reader, writer = socket.socketpair()
        with reader, writer:
            reader.settimeout(60)
            launch = 'import os,sys; os.dup2(int(sys.argv[1]),3); os.execv(sys.argv[2],sys.argv[2:])'
            with subprocess.Popen([sys.executable, '-c', launch, str(writer.fileno()), worker, *args],
                                  pass_fds=(writer.fileno(),), cwd=home, stdin=subprocess.DEVNULL,
                                  env=dict(HOME=home, PATH='/usr/bin:/bin'), stdout=log, stderr=log) as proc:
                writer.close()
                try:
                    with reader.makefile('rb') as stream:
                        for op, profile, reply in requests:
                            header = stream.read(4)
                            if len(header) != 4:
                                log.seek(0)
                                raise AssertionError((args, 'missing request', log.read()))
                            size, = struct.unpack('!I', header)
                            msg = json.loads(stream.read(size))
                            assert (msg['op'], msg['profile']) == (op, profile), (args, msg['op'], msg['profile'])
                            if op == 'delete':
                                assert msg['expected'] == session
                            frame = json.dumps(reply).encode()
                            reader.sendall(struct.pack('!I', len(frame)) + frame)
                        assert not stream.read(1), (args, 'unexpected request')
                    proc.wait(timeout=30)
                finally:
                    proc.kill()
        log.seek(0)
        output = log.read().decode()
        assert (proc.returncode == 0) == success and expected in output, (args, output)
        for file in Path(home).rglob('*'):
            if file.is_file():
                assert token.encode() not in file.read_bytes(), file
        print(worker.parent.parent.parent.name, *args, 'OK', flush=True)


check(doctl, ['version'], [], True, sys.argv[2])
check(doctl, ['auth', 'token', '--context', 'work'], [('use', 'work', dict(ok=True, value=session))], True, token)
check(doctl, ['account', 'get'], [('use', 'default', deny)], False, 'fixture approval denied')
check(doctl, ['auth', 'remove', '--context', 'default'],
      [('use', 'default', dict(ok=True, value=session)), ('delete', 'default', dict(ok=True, value=None))], True, '')
