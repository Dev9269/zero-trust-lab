def test_public_page_has_classification_header(demo_app_module):
    client = demo_app_module.app.test_client()
    response = client.get("/public")

    assert response.status_code == 200
    assert response.headers.get("X-Data-Classification") == "PUBLIC"
    assert response.headers.get("X-Data-Encryption-Required") == "false"
    assert response.headers.get("X-Data-Retention-Days") == "90"


def test_sensitive_page_has_classification_header(demo_app_module):
    client = demo_app_module.app.test_client()
    response = client.get("/sensitive")

    assert response.status_code == 200
    assert response.headers.get("X-Data-Classification") == "CONFIDENTIAL"
    assert response.headers.get("X-Data-Encryption-Required") == "true"
    assert response.headers.get("X-Data-Retention-Days") == "30"


def test_api_data_returns_filtered_by_clearance(demo_app_module):
    """With no clearance header (defaults to anonymous=0),
    only PUBLIC objects should be returned."""
    client = demo_app_module.app.test_client()
    response = client.get("/api/data")

    assert response.status_code == 200
    data = response.get_json()
    assert data["classification"] == "INTERNAL"
    assert "objects" in data
    assert "public-announcement" in data["objects"]
    assert "employee-records" not in data["objects"]
    assert "encryption-keys" not in data["objects"]


def test_api_data_admin_clearance_sees_all(demo_app_module):
    """With admin clearance, all objects should be visible."""
    client = demo_app_module.app.test_client()
    response = client.get(
        "/api/data",
        headers={"X-ZTLab-Clearance": "clearance=admin"},
    )

    assert response.status_code == 200
    data = response.get_json()
    assert "public-announcement" in data["objects"]
    assert "employee-records" in data["objects"]
    assert "encryption-keys" in data["objects"]


def test_api_data_restricted_object_denied_without_clearance(demo_app_module):
    """Without sufficient clearance, RESTRICTED objects return 403."""
    client = demo_app_module.app.test_client()
    response = client.get("/api/data/encryption-keys")

    assert response.status_code == 403
    assert response.get_json()["error"] == "insufficient clearance"


def test_api_data_restricted_object_allowed_with_admin(demo_app_module):
    """With admin clearance, RESTRICTED objects are accessible."""
    client = demo_app_module.app.test_client()
    response = client.get(
        "/api/data/encryption-keys",
        headers={"X-ZTLab-Clearance": "clearance=admin"},
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["id"] == "encryption-keys"
    assert data["classification"] == "RESTRICTED"


def test_api_data_confidential_denied_without_clearance(demo_app_module):
    """CONFIDENTIAL object returns 403 when caller has no clearance."""
    client = demo_app_module.app.test_client()
    response = client.get("/api/data/employee-records")

    assert response.status_code == 403
    assert response.get_json()["error"] == "insufficient clearance"


def test_api_data_confidential_allowed_with_devops(demo_app_module):
    """CONFIDENTIAL objects are accessible with devops or higher clearance."""
    client = demo_app_module.app.test_client()
    response = client.get(
        "/api/data/employee-records",
        headers={"X-ZTLab-Clearance": "clearance=devops"},
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["id"] == "employee-records"
    assert data["classification"] == "CONFIDENTIAL"
    assert data["owner"] == "hr@zerotrust.lab"


def test_api_data_object_not_found(demo_app_module):
    client = demo_app_module.app.test_client()
    response = client.get("/api/data/nonexistent")

    assert response.status_code == 404


def test_public_page_shows_classification_badge(demo_app_module):
    client = demo_app_module.app.test_client()
    response = client.get("/public")

    assert b"PUBLIC DATA" in response.data


def test_sensitive_page_shows_classification_badge(demo_app_module):
    client = demo_app_module.app.test_client()
    response = client.get("/sensitive")

    assert b"CONFIDENTIAL DATA" in response.data


def test_healthz_still_works(demo_app_module):
    response = demo_app_module.app.test_client().get("/healthz")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
