import subprocess
import sys
import os
import time

# --- Configuration ---
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend_api")
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "dashboard_frontend")
BACKEND_REQUIREMENTS = os.path.join(BACKEND_DIR, "requirements.txt")

# --- Helper Functions ---
def run_command(command, cwd=PROJECT_ROOT, check_error=True):
    print(f"\nRunning command: {' '.join(command)} in {cwd}")
    process = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if check_error and process.returncode != 0:
        print(f"Error: Command failed with exit code {process.returncode}")
        print("Stdout:", process.stdout)
        print("Stderr:", process.stderr)
        sys.exit(1)
    print("Stdout:", process.stdout)
    if process.stderr:
        print("Stderr:", process.stderr)
    return process

def start_process_background(command, cwd=PROJECT_ROOT):
    print(f"\nStarting background process: {' '.join(command)} in {cwd}")
    # Use preexec_fn to make the child process a process group leader
    # This allows killing the entire group later
    process = subprocess.Popen(command, cwd=cwd, text=True, preexec_fn=os.setsid, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"Process started with PID: {process.pid}")
    return process

# --- Main Deployment Logic ---
def deploy_phantomnet():
    print("--- Starting PhantomNet Deployment ---")

    # 1. Install Python Dependencies
    print("\n--- Installing Python Dependencies for Backend ---")
    run_command([sys.executable, "-m", "pip", "install", "-r", BACKEND_REQUIREMENTS])

    # 2. Initialize Database
    print("\n--- Initializing Database ---")
    # Ensure test.db is removed to start fresh, as it's used by the backend
    if os.path.exists(os.path.join(BACKEND_DIR, "test.db")):
        os.remove(os.path.join(BACKEND_DIR, "test.db"))
        print("Removed existing test.db to ensure a fresh start.")
    run_command([sys.executable, os.path.join(BACKEND_DIR, "database.py")])

    # 3. Install Node.js Dependencies for Frontend
    print("\n--- Installing Node.js Dependencies for Frontend ---")
    run_command(["npm", "install"], cwd=FRONTEND_DIR)

    # 4. Build Frontend
    print("\n--- Building Frontend ---")
    run_command(["npm", "run", "build"], cwd=FRONTEND_DIR)

    # 5. Start Backend API
    print("\n--- Starting Backend API (FastAPI) ---")
    # Assuming the main app is in backend_api/api_gateway/app.py
    # and can be run with uvicorn
    backend_process = start_process_background(
        [sys.executable, "-m", "uvicorn", "backend_api.api_gateway.app:app", "--host", "0.0.0.0", "--port", "8000"],
        cwd=PROJECT_ROOT
    )
    print(f"Backend API started. PID: {backend_process.pid}")
    print("Waiting a few seconds for the backend to spin up...")
    time.sleep(5) # Give the backend some time to start

    # 6. Start Frontend Development Server (or serve build)
    print("\n--- Starting Frontend Development Server ---")
    # For production, you'd serve the build directory with a static file server
    # For quick start, we'll use npm start which usually runs a dev server
    frontend_process = start_process_background(["npm", "start"], cwd=FRONTEND_DIR)
    print(f"Frontend server started. PID: {frontend_process.pid}")
    print("Waiting a few seconds for the frontend to spin up...")
    time.sleep(10) # Give the frontend some time to start

    print("\n--- Deployment Complete! ---")
    print(f"PhantomNet Backend API should be running on: http://0.0.0.0:8000")
    print(f"PhantomNet Frontend Dashboard should be running on: http://localhost:3000 (or similar, check npm output)")
    print("\nTo stop the services, you may need to manually kill the processes:")
    print(f"  Backend PID: {backend_process.pid}")
    print(f"  Frontend PID: {frontend_process.pid}")
    print("Or find them using `ps aux | grep python` and `ps aux | grep node` and kill them.")

    # Keep the script running to keep background processes alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n--- Shutting down PhantomNet services ---")
        # Terminate the process groups
        if backend_process.poll() is None:
            os.killpg(os.getpgid(backend_process.pid), 15) # SIGTERM
            print(f"Sent SIGTERM to backend process group {os.getpgid(backend_process.pid)}")
        if frontend_process.poll() is None:
            os.killpg(os.getpgid(frontend_process.pid), 15) # SIGTERM
            print(f"Sent SIGTERM to frontend process group {os.getpgid(frontend_process.pid)}")
        print("Services shut down.")
        sys.exit(0)

if __name__ == "__main__":
    deploy_phantomnet()
