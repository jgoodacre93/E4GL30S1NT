"""Tests for breach intelligence provider."""
import pytest
from unittest.mock import MagicMock, patch

from eagleosint.providers.breach import (
    BreachProvider,
    _query_dehashed,
    _query_hibp,
    _query_leakcheck,
)
from eagleosint.models import BreachResult


class TestQueryHibp:
    @patch("eagleosint.providers.breach._session")
    def test_found_breaches(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {
                "Name": "LinkedIn",
                "BreachDate": "2012-05-05",
                "DataClasses": ["Email addresses", "Passwords"],
                "Domain": "linkedin.com",
                "Description": "LinkedIn breach",
                "IsVerified": True,
                "IsSensitive": False,
            },
            {
                "Name": "Adobe",
                "BreachDate": "2013-10-04",
                "DataClasses": ["Email addresses", "Passwords", "Usernames"],
                "Domain": "adobe.com",
                "Description": "Adobe breach",
                "IsVerified": True,
                "IsSensitive": False,
            },
        ]
        mock_session.get.return_value = mock_resp

        results = _query_hibp("test@example.com", "fake-key")
        assert len(results) == 2
        assert results[0].breach_name == "LinkedIn"
        assert results[0].breach_date == "2012-05-05"
        assert "Passwords" in results[0].exposed_data
        assert results[0].domain == "linkedin.com"
        assert results[1].breach_name == "Adobe"

    @patch("eagleosint.providers.breach._session")
    def test_no_breaches_404(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_session.get.return_value = mock_resp

        results = _query_hibp("clean@example.com", "fake-key")
        assert results == []

    @patch("eagleosint.providers.breach._session")
    def test_rate_limited_429(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_session.get.return_value = mock_resp

        results = _query_hibp("test@example.com", "fake-key")
        assert results == []

    @patch("eagleosint.providers.breach._session")
    def test_request_exception(self, mock_session):
        import requests
        mock_session.get.side_effect = requests.exceptions.ConnectionError("timeout")

        results = _query_hibp("test@example.com", "fake-key")
        assert results == []

    @patch("eagleosint.providers.breach._session")
    def test_sensitive_breach_flagged(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {
                "Name": "SensitiveSite",
                "DataClasses": ["Email addresses"],
                "IsVerified": True,
                "IsSensitive": True,
            },
        ]
        mock_session.get.return_value = mock_resp

        results = _query_hibp("test@example.com", "fake-key")
        assert results[0].is_sensitive is True


class TestQueryDehashed:
    @patch("eagleosint.providers.breach._session")
    def test_found_entries(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "entries": [
                {
                    "database_name": "LinkedInDB",
                    "email": "test@example.com",
                    "hashed_password": "abc123",
                    "username": "testuser",
                },
                {
                    "database_name": "AdobeDB",
                    "email": "test@example.com",
                    "password": "plain",
                },
            ]
        }
        mock_session.get.return_value = mock_resp

        results = _query_dehashed("test@example.com", "fake-key", "me@email.com")
        assert len(results) == 2
        assert results[0].breach_name == "LinkedInDB"
        assert "Passwords" in results[0].exposed_data
        assert "Usernames" in results[0].exposed_data

    @patch("eagleosint.providers.breach._session")
    def test_deduplicates_same_db(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "entries": [
                {"database_name": "SameDB", "email": "a@a.com"},
                {"database_name": "SameDB", "email": "a@a.com"},
                {"database_name": "SameDB", "email": "a@a.com"},
            ]
        }
        mock_session.get.return_value = mock_resp

        results = _query_dehashed("a@a.com", "key", "me@email.com")
        assert len(results) == 1

    @patch("eagleosint.providers.breach._session")
    def test_invalid_credentials_401(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_session.get.return_value = mock_resp

        results = _query_dehashed("test@example.com", "bad-key", "me@email.com")
        assert results == []

    @patch("eagleosint.providers.breach._session")
    def test_empty_entries(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"entries": None}
        mock_session.get.return_value = mock_resp

        results = _query_dehashed("test@example.com", "key", "me@email.com")
        assert results == []


class TestQueryLeakcheck:
    @patch("eagleosint.providers.breach._session")
    def test_found_leaks(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "success": True,
            "result": [
                {
                    "sources": [
                        {"name": "Collection1", "date": "2019-01-01"},
                        {"name": "LinkedIn", "date": "2012-05-05"},
                    ]
                }
            ],
        }
        mock_session.get.return_value = mock_resp

        results = _query_leakcheck("test@example.com", "fake-key")
        assert len(results) == 2
        assert results[0].breach_name == "Collection1"
        assert results[0].breach_date == "2019-01-01"
        assert results[1].breach_name == "LinkedIn"

    @patch("eagleosint.providers.breach._session")
    def test_not_found_404(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_session.get.return_value = mock_resp

        results = _query_leakcheck("clean@example.com", "fake-key")
        assert results == []

    @patch("eagleosint.providers.breach._session")
    def test_invalid_key_401(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_session.get.return_value = mock_resp

        results = _query_leakcheck("test@example.com", "bad-key")
        assert results == []

    @patch("eagleosint.providers.breach._session")
    def test_success_false(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"success": False}
        mock_session.get.return_value = mock_resp

        results = _query_leakcheck("test@example.com", "key")
        assert results == []


class TestBreachProvider:
    @patch("eagleosint.providers.breach.settings")
    @patch("eagleosint.providers.breach._session")
    def test_all_services_called(self, mock_session, mock_settings):
        mock_settings.get_key.side_effect = lambda k: {
            "hibp-api-key": "hk",
            "dehashed-api-key": "dk",
            "dehashed-email": "de@e.com",
            "leakcheck-api-key": "lk",
        }.get(k)

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_session.get.return_value = mock_resp

        provider = BreachProvider()
        results = provider.execute("test@example.com")
        assert mock_session.get.call_count == 3

    @patch("eagleosint.providers.breach.settings")
    def test_no_keys_configured(self, mock_settings):
        mock_settings.get_key.return_value = None

        provider = BreachProvider()
        results = provider.execute("test@example.com")
        assert results == []

    @patch("eagleosint.providers.breach.settings")
    @patch("eagleosint.providers.breach._session")
    def test_only_hibp_when_only_hibp_key(self, mock_session, mock_settings):
        mock_settings.get_key.side_effect = lambda k: "hk" if k == "hibp-api-key" else None

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_session.get.return_value = mock_resp

        provider = BreachProvider()
        results = provider.execute("test@example.com")
        assert mock_session.get.call_count == 1

    @patch("eagleosint.providers.breach.settings")
    @patch("eagleosint.providers.breach._session")
    def test_results_are_breach_result_type(self, mock_session, mock_settings):
        mock_settings.get_key.side_effect = lambda k: "hk" if k == "hibp-api-key" else None

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"Name": "TestBreach", "DataClasses": ["Emails"], "IsVerified": True, "IsSensitive": False}
        ]
        mock_session.get.return_value = mock_resp

        provider = BreachProvider()
        results = provider.execute("test@example.com")
        assert len(results) == 1
        assert isinstance(results[0], BreachResult)
        assert results[0].source == "hibp"