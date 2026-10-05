import os
import tempfile

# Each test invocation gets an isolated database and artifact store.
os.environ['ECDAT_STATE']=tempfile.mkdtemp(prefix='ecdat-tests-')
os.environ['ECDAT_DEMO']='1'
os.environ['ECDAT_WORKER']='0'
os.environ['ECDAT_MEMORY_RESERVE_MB']='0'
