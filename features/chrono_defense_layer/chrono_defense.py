import os
import shutil
import datetime

class ChronoDefense:
    """
    Real-time temporal rollback for compromised systems.
    PhantomNet can reverse an environment to its pre-attack state.
    """
    def __init__(self, snapshot_dir="snapshots"):
        self.snapshot_dir = snapshot_dir
        if not os.path.exists(self.snapshot_dir):
            os.makedirs(self.snapshot_dir)
        print("Initializing ChronoDefense Layer...")

    def create_snapshot(self, target_file: str):
        """
        Creates a timestamped snapshot of the target file.
        """
        if not os.path.exists(target_file):
            print(f"Error: Target file {target_file} does not exist.")
            return None
            
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        snapshot_name = f"{os.path.basename(target_file)}_{timestamp}.snapshot"
        snapshot_path = os.path.join(self.snapshot_dir, snapshot_name)
        
        shutil.copy2(target_file, snapshot_path)
        print(f"Created snapshot: {snapshot_path}")
        return snapshot_path

    def get_latest_snapshot(self, target_file: str):
        """
        Finds the most recent snapshot for a given target file.
        """
        file_basename = os.path.basename(target_file)
        snapshots = [s for s in os.listdir(self.snapshot_dir) if s.startswith(file_basename) and s.endswith(".snapshot")]
        
        if not snapshots:
            return None
            
        return os.path.join(self.snapshot_dir, sorted(snapshots, reverse=True)[0])

    def rollback_to_snapshot(self, target_file: str, snapshot_path: str):
        """
        Rolls back the target file to the state of the given snapshot.
        """
        if not os.path.exists(snapshot_path):
            print(f"Error: Snapshot file {snapshot_path} does not exist.")
            return False
            
        shutil.copy2(snapshot_path, target_file)
        print(f"Rolled back {target_file} to snapshot {snapshot_path}")
        return True

    def cleanup_snapshots(self):
        """
        Removes the snapshot directory and all its contents.
        """
        if os.path.exists(self.snapshot_dir):
            shutil.rmtree(self.snapshot_dir)
            print(f"Cleaned up snapshot directory: {self.snapshot_dir}")