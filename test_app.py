from fastapi.testclient import TestClient
from app.main import app
from app.db import SessionLocal, School


EXPECTED_SCHOOLS = 17922  # 17,951 national rows - 104 Kaliningrad rows + 75 legacy Kaliningrad entries


def test_health_catalog_and_city_rating():
    with TestClient(app) as client:
        assert client.get('/health').status_code == 200
        cities = client.get('/api/cities')
        assert cities.status_code == 200
        payload = cities.json()
        assert len(payload['cities']) >= 296
        with SessionLocal() as db:
            count = db.query(School).count()
            assert count == EXPECTED_SCHOOLS
            kal_count = db.query(School).filter(School.city == 'Калининград').count()
            assert kal_count == 75
        city = payload['cities'][0]['name']
        cat = client.get('/api/cities/' + city + '/categories')
        assert cat.status_code == 200
        assert cat.json()['categories']
        lb = client.get('/api/leaderboard')
        assert lb.status_code == 200
        assert len(lb.json()['items']) <= 100
        cities_lb = client.get('/api/leaderboard?scope=cities')
        assert cities_lb.status_code == 200
        assert cities_lb.json()['scope'] == 'cities'


def test_session_and_stats_are_lifetime_based():
    with TestClient(app) as client:
        a = client.get('/api/session').json()
        b = client.get('/api/session').json()
        assert a['visitor'] == b['visitor']
        stats = client.get('/api/stats').json()
        assert 'total_visitors' in stats
        assert 'unique_today' not in stats
        assert 'schools_playing' in stats


def test_clicks_are_batched_and_duplicate_request_is_ignored():
    with TestClient(app) as client:
        # Use a known bundled school.
        school_id = 'bfu_kant'
        first = client.post('/api/clicks', json={'school_id': school_id, 'clicks': 30, 'request_id': '1234567890abcdef-batch-1'})
        assert first.status_code == 200
        assert first.json()['accepted'] == 30
        duplicate = client.post('/api/clicks', json={'school_id': school_id, 'clicks': 30, 'request_id': '1234567890abcdef-batch-1'})
        assert duplicate.status_code == 200
        assert duplicate.json()['accepted'] == 0
        assert duplicate.json().get('duplicate') is True


def test_click_limit_is_rolling_800_per_minute():
    with TestClient(app) as client:
        school_id = 'bfu_kant'
        r = client.post('/api/clicks', headers={'User-Agent':'Mozilla/5.0 rolling-test'}, json={'school_id': school_id, 'clicks': 800, 'request_id': '1234567890abcdef-rolling-1'})
        assert r.status_code == 200
        assert r.json()['accepted'] == 800 or r.json()['rejected'] == 0
        r2 = client.post('/api/clicks', headers={'User-Agent':'Mozilla/5.0 rolling-test'}, json={'school_id': school_id, 'clicks': 1, 'request_id': '1234567890abcdef-rolling-2'})
        assert r2.status_code in (200, 429)
        if r2.status_code == 200:
            assert r2.json()['accepted'] == 0
