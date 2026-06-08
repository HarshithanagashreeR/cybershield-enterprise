#!/usr/bin/env python3
import sys
import subprocess
import os

def get_python_executable():
    # Detect if a venv is available and use it if we are running on system python
    root_dir = os.path.dirname(os.path.abspath(__file__))
    possible_paths = [
        os.path.join(root_dir, "venv", "bin", "python3"),
        os.path.join(root_dir, "venv", "bin", "python"),
        os.path.join(root_dir, "venv", "Scripts", "python.exe")
    ]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    return sys.executable

if __name__ == "__main__":
    # Get run.py path
    run_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "run.py")
    python_exe = get_python_executable()
    
    # Execute run.py using the correct python (pass through arguments or default to prod)
    cmd = [python_exe, run_py]
    if len(sys.argv) > 1:
        cmd.extend(sys.argv[1:])
    else:
        cmd.append("prod")
        
    shell = sys.platform == "win32"
    try:
        sys.exit(subprocess.run(cmd, shell=shell).returncode)
    except KeyboardInterrupt:
        sys.exit(0)
