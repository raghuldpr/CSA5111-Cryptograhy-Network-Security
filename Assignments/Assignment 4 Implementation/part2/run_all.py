"""Run every Part II task and refresh outputs/. Requires: Python 3.10+, `pip install cryptography`, `openssl` on PATH (Task 2, 4)."""
import os, subprocess, sys
here = os.path.dirname(os.path.abspath(__file__))
os.makedirs(os.path.join(here, "outputs"), exist_ok=True)
for name, script in [("task1", "task1_run.py"), ("task2", "task2_run.py"), ("task3", "task3_esp.py"),
                     ("task4", "task4_https.py"), ("task5", "task5_mailauth.py"), ("task6", "task6_bulk.py")]:
    p = subprocess.run([sys.executable, os.path.join(here, script)], capture_output=True, text=True, encoding="utf-8",
                       env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    open(os.path.join(here, "outputs", f"{name}_output.txt"), "w", encoding="utf-8").write(p.stdout + p.stderr)
    print(f"{name}: exit {p.returncode}")
