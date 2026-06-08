import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
print('ROOT on sys.path =', sys.path[0])
try:
    import services.rag_engine as re
    print('imported services.rag_engine ok')
    print('RAG module path:', re.__file__)
except Exception as e:
    print('import failed:', type(e), e)
    import traceback
    traceback.print_exc()
