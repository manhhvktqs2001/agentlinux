import os
import subprocess

def kill_process(process_id, force_kill=True):
    try:
        sig = '-9' if force_kill else '-15'
        cmd = ["kill", sig, str(process_id)]
        subprocess.run(cmd, check=True)
        print(f"[AGENT] Killed process {process_id} (force={force_kill})")
        return True
    except Exception as e:
        print(f"[AGENT] Failed to kill process {process_id}: {e}")
        return False
