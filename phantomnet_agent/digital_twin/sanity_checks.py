import re
from .models import TwinTemplate
from typing import List

AWS_KEY_PAT = re.compile(r'AKIA[0-9A-Z]{16}')

def validate_no_real_keys(template: TwinTemplate) -> List[str]:
    problems = []
    raw = template.json()
    if AWS_KEY_PAT.search(raw):
        problems.append("Found AWS-like access key")
    return problems
