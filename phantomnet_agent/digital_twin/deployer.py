import tempfile
import os
import subprocess
import shutil
from .models import TwinInstance

def deploy_instance(instance: TwinInstance, workdir_base="/var/lib/phantomnet/instances"):
    # create workdir
    wd = os.path.join(workdir_base, instance.instance_id)
    os.makedirs(wd, exist_ok=True)
    path = os.path.join(wd, "docker-compose.yml")
    with open(path, "w") as f:
        f.write(instance.docker_compose_yaml)
    # run docker-compose
    if os.getenv("DEPLOY_ALLOW") == "true":
        subprocess.run(["docker", "compose", "up", "-d"], cwd=wd, check=True)
    else:
        print("Dry-run mode: docker-compose command not executed.")
    return wd
