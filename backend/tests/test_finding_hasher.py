from app.services.finding_hasher import stable_key

def test_stable_key_is_deterministic():
    k1 = stable_key("fortify", "SQL Injection", "SQL Injection in login.py")
    k2 = stable_key("fortify", "SQL Injection", "SQL Injection in login.py")
    assert k1 == k2

def test_different_inputs_differ():
    k1 = stable_key("fortify", "SQL Injection", "title A")
    k2 = stable_key("fortify", "XSS", "title A")
    assert k1 != k2

def test_case_insensitive_title():
    k1 = stable_key("fortify", "SQL", "My Finding")
    k2 = stable_key("fortify", "SQL", "my finding")
    assert k1 == k2
