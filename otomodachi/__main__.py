
import argparse
from .nexauth import NexAuth

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--export-credentials', action='store_true')
    parser.add_argument('--file', type=str, required=True)
    args = parser.parse_args()

    if args.export_credentials:
        nexAuth = NexAuth()
        nexAuth.dump(args.file)

main()


