import uuid
import datetime
import yaml
import jinja2
from .models import TwinTemplate, TwinInstance

def render_template(template: TwinTemplate, params: dict) -> TwinInstance:
    inst_id = f"twin-{uuid.uuid4().hex[:8]}"
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    # render service files using Jinja2 for placeholders
    compose = {"version": "3.8", "services": {}}
    for svc in template.services:
        name = svc.name
        service_def = {"image": svc.image or "alpine:latest", "environment": svc.env, "ports": svc.ports}
        # add volumes for files; create local bind-mounts with generated content
        compose["services"][name] = service_def
    docker_compose_yaml = yaml.dump(compose)
    instance = TwinInstance(
        instance_id=inst_id,
        template_id=template.template_id,
        created_at=ts,
        params=params,
        docker_compose_yaml=docker_compose_yaml
    )
    return instance
