import json
import sys
from pathlib import Path
from .discovery import scan_directory

if __name__ == '__main__':
    print(json.dumps(scan_directory(Path(sys.argv[1]))))
