# Drive setup-ad-signin.sh in a pseudo-terminal: argv[1] = temp dir with src/, dest/, cfg.json; the rest = answers, one per prompt.
import os, pty, sys, time, select, re
S=sys.argv[1]; answers=sys.argv[2:]
env=dict(os.environ, AS_AUTH_DEST=S+'/dest', AS_AUTH_CFG=S+'/cfg.json')
pid, fd = pty.fork()
if pid==0:
    os.execvpe('bash',['bash',S+'/src/setup-ad-signin.sh'],env)
buf=b''; ai=0; last=time.time()
while True:
    r,_,_=select.select([fd],[],[],0.3)
    if r:
        try: d=os.read(fd,4096)
        except OSError: break
        if not d: break
        buf+=d; last=time.time(); continue
    if time.time()-last>0.6 and ai<len(answers):
        os.write(fd,(answers[ai]+'\n').encode()); ai+=1; last=time.time()
    if time.time()-last>20: break
_,st=os.waitpid(pid,0)
print(buf.decode(errors='replace')); print('EXIT',os.waitstatus_to_exitcode(st))
