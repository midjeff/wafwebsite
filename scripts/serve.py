"""Optional developer preview; Docker copies each implementation as package portal."""
import argparse
import importlib.util
import sys
from pathlib import Path

from waitress import serve

parser = argparse.ArgumentParser()
parser.add_argument("variant", choices=["app", "app-fixed"])
parser.add_argument("--port", type=int, required=True)
args = parser.parse_args()
folder = Path(__file__).resolve().parents[1] / args.variant
spec = importlib.util.spec_from_file_location("portal", folder / "__init__.py", submodule_search_locations=[str(folder)])
module = importlib.util.module_from_spec(spec)
sys.modules["portal"] = module
spec.loader.exec_module(module)
from portal.main import create_app

print(f"NEXUS {args.variant}: http://127.0.0.1:{args.port}", flush=True)
serve(create_app(), host="127.0.0.1", port=args.port, threads=4)
