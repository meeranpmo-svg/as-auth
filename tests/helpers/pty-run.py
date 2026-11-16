# Run a command in a pseudo-terminal and type the given chunks (JSON list) one after another, ~0.6 s apart. Prints the screen.
import os, pty, sys, time, select, json
chunks = json.loads(sys.argv[1]); cmd = sys.argv[2:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)
buf = b''; i = 0; last = time.time(); start = time.time()
while time.time() - start < 25:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try: d = os.read(fd, 4096)
        except OSError: break
        if not d: break
        buf += d; last = time.time(); continue
    if i < len(chunks) and time.time() - last > 0.6:
        os.write(fd, chunks[i].encode()); i += 1; last = time.time()
    try:
        if os.waitpid(pid, os.WNOHANG)[0]: break
    except ChildProcessError: break
sys.stdout.write(buf.decode(errors='replace'))
