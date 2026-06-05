import psutil

def kill_suspicious_process(pid):
    """
    Attempts to terminate a process by its PID.
    Returns True if successful, False otherwise.
    """
    try:
        process = psutil.Process(pid)
        process.terminate()
        process.wait(timeout=3)
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
        print(f"Error al terminar el proceso {pid}: {e}")
        try:
            # Force kill if terminate fails
            process.kill()
            return True
        except:
            return False

def close_unauthorized_connection(pid):
    """
    Wrapper for kill_suspicious_process for clarity in the UI.
    """
    return kill_suspicious_process(pid)
