#!/usr/bin/env python3

import sys

if len(sys.argv) != 2:
    sys.exit(f"Usage: {sys.argv[0]} NETID")

netid = sys.argv[1]
with open("artifact.md", "w") as f:
    f.write(f"{netid}\n")

print("created artifact.md")
