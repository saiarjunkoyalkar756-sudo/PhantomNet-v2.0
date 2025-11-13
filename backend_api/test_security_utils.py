import pytest
from datetime import datetime, timedelta
import jwt

from backend_api.security_utils import create_inter_node_jwt, verify_inter_node_jwt, generate_key_pair, used_jtis

@pytest.fixture(autouse=True)
def clear_used_jtis():
    used_jtis.clear()

def test_create_and_verify_jwt():
    private_key, public_key = generate_key_pair()
    agent_id = 1
    cluster_id = "test_cluster"
    scope = "agent:heartbeat"

    token = create_inter_node_jwt(agent_id, cluster_id, scope, private_key)
    decoded_payload = verify_inter_node_jwt(token, public_key, cluster_id)

    assert decoded_payload["iss"] == str(agent_id)
    assert decoded_payload["sub"] == str(agent_id)
    assert decoded_payload["aud"] == cluster_id
    assert decoded_payload["scope"] == scope
    assert "jti" in decoded_payload

def test_verify_jwt_bad_signature():
    private_key, public_key = generate_key_pair()
    _, wrong_public_key = generate_key_pair()
    agent_id = 1
    cluster_id = "test_cluster"
    scope = "agent:heartbeat"

    token = create_inter_node_jwt(agent_id, cluster_id, scope, private_key)

    with pytest.raises(jwt.InvalidSignatureError):
        verify_inter_node_jwt(token, wrong_public_key, cluster_id)

def test_verify_jwt_wrong_audience():
    private_key, public_key = generate_key_pair()
    agent_id = 1
    cluster_id = "test_cluster"
    scope = "agent:heartbeat"

    token = create_inter_node_jwt(agent_id, cluster_id, scope, private_key)

    with pytest.raises(jwt.InvalidAudienceError):
        verify_inter_node_jwt(token, public_key, "wrong_cluster")

def test_verify_jwt_expired_token():
    private_key, public_key = generate_key_pair()
    agent_id = 1
    cluster_id = "test_cluster"
    scope = "agent:heartbeat"

    # Create an expired token
    now = datetime.utcnow()
    payload = {
        "iss": str(agent_id),
        "sub": str(agent_id),
        "aud": cluster_id,
        "iat": now - timedelta(minutes=5),
        "exp": now - timedelta(minutes=1), # Expired
        "jti": str(uuid.uuid4()),
        "scope": scope,
    }
    expired_token = jwt.encode(payload, private_key, algorithm="RS256")

    with pytest.raises(jwt.ExpiredSignatureError):
        verify_inter_node_jwt(expired_token, public_key, cluster_id)

def test_verify_jwt_reused_jti():
    private_key, public_key = generate_key_pair()
    agent_id = 1
    cluster_id = "test_cluster"
    scope = "agent:heartbeat"

    token = create_inter_node_jwt(agent_id, cluster_id, scope, private_key)
    verify_inter_node_jwt(token, public_key, cluster_id) # First use

    with pytest.raises(jwt.InvalidTokenError, match="JWT ID \(jti\) has been used already."):
        verify_inter_node_jwt(token, public_key, cluster_id) # Attempt to reuse