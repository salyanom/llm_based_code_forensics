import os
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
print('ROOT=', ROOT)
print('services exists =', os.path.isdir(os.path.join(ROOT, 'services')))
print('services listing =', os.listdir(os.path.join(ROOT))[:50])
