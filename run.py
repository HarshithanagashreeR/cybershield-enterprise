#!/usr/bin/env python3
import subprocess
import sys
import os
import signal
import time
from threading import Thread

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")

# Active subprocesses
processes = []

def signal_handler(sig, frame):
    print("\n⏹️ Shutting down processes...")
    for p in processes:
        try:
            p.terminate()
        except:
            pass
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def run_command_stream(command, cwd, prefix):
    """Run a command and print output line by line with a prefix."""
    shell = sys.platform == "win32"
    p = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        shell=shell
    )
    processes.append(p)
    
    # Read output line by line
    for line in iter(p.stdout.readline, ""):
        print(f"[{prefix}] {line.strip()}")
    
    p.stdout.close()
    p.wait()
    if p in processes:
        processes.remove(p)

def run_dev():
    print("🚀 Starting Security Assessment Platform in DEVELOPMENT mode...")
    
    # 1. Start Backend FastAPI
    # Ensure dependencies are installed or check venv
    venv_python = sys.executable
    backend_cmd = [venv_python, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000", "--reload"]
    
    t_backend = Thread(target=run_command_stream, args=(backend_cmd, BACKEND_DIR, "BACKEND"), daemon=True)
    t_backend.start()
    
    # Wait a bit for backend to initialize
    time.sleep(1.5)
    
    # 2. Check if npm packages are installed in frontend
    node_modules_path = os.path.join(FRONTEND_DIR, "node_modules")
    if not os.path.exists(node_modules_path):
        print("📦 Node modules not found. Installing frontend dependencies...")
        shell = sys.platform == "win32"
        subprocess.run(["npm", "install"], cwd=FRONTEND_DIR, shell=shell)
        
    # 3. Start Frontend Vite
    frontend_cmd = ["npm", "run", "dev"]
    t_frontend = Thread(target=run_command_stream, args=(frontend_cmd, FRONTEND_DIR, "FRONTEND"), daemon=True)
    t_frontend.start()
    
    print("\n" + "="*80)
    print("  🖥️  Web UI running at: http://localhost:5173")
    print("  ⚙️  API running at:    http://localhost:8000")
    print("  ⏹️  Press CTRL+C to stop both servers")
    print("="*80 + "\n")
    
    # Keep main thread alive
    while True:
        time.sleep(1)

def run_build():
    print("🔨 Compiling React frontend build...")
    shell = sys.platform == "win32"
    
    # npm install if node_modules missing
    node_modules_path = os.path.join(FRONTEND_DIR, "node_modules")
    if not os.path.exists(node_modules_path):
        print("📦 Installing frontend dependencies...")
        subprocess.run(["npm", "install"], cwd=FRONTEND_DIR, shell=shell)
        
    # npm run build
    result = subprocess.run(["npm", "run", "build"], cwd=FRONTEND_DIR, shell=shell)
    if result.returncode == 0:
        print("✅ Frontend build compiled successfully in frontend/dist")
    else:
        print("❌ Frontend compilation failed.")
        sys.exit(1)

def run_prod():
    print("🚀 Starting unified production server on port 8000...")
    
    dist_path = os.path.join(FRONTEND_DIR, "dist")
    if not os.path.exists(dist_path):
        print("⚠️ Warning: Production build folder (frontend/dist) not found. Building first...")
        run_build()
        
    venv_python = sys.executable
    backend_cmd = [venv_python, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
    
    print("\n" + "="*80)
    print("  🌐 Live Web UI: http://localhost:8000")
    print("  ⏹️  Press CTRL+C to stop the production server")
    print("="*80 + "\n")
    
    # Run synchronously in main thread
    shell = sys.platform == "win32"
    p = subprocess.Popen(backend_cmd, cwd=BACKEND_DIR, shell=shell)
    processes.append(p)
    p.wait()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run.py [dev|build|prod]")
        sys.exit(1)
        
    action = sys.argv[1].lower()
    if action == "dev":
        run_dev()
    elif action == "build":
        run_build()
    elif action == "prod":
        run_prod()
    else:
        print(f"Unknown action: {action}")
        print("Usage: python run.py [dev|build|prod]")
        sys.exit(1)
