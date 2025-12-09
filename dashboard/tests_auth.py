from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from dashboard.auth import KeycloakOIDCBackend
from unittest.mock import MagicMock

User = get_user_model()

@override_settings(
    OIDC_OP_TOKEN_ENDPOINT='http://localhost/token',
    OIDC_OP_AUTHORIZATION_ENDPOINT='http://localhost/auth',
    OIDC_OP_USER_ENDPOINT='http://localhost/userinfo',
    OIDC_RP_CLIENT_ID='test-client',
    OIDC_RP_CLIENT_SECRET='test-secret',
    OIDC_OP_JWKS_ENDPOINT='http://localhost/certs',
    OIDC_RP_SIGN_ALGO='RS256' 
)
class KeycloakBackendTest(TestCase):
    def setUp(self):
        self.backend = KeycloakOIDCBackend()

    def test_create_user_with_roles(self):
        claims = {
            'preferred_username': 'testuser',
            'email': 'test@example.com',
            'given_name': 'Test',
            'family_name': 'User',
            'realm_access': {
                'roles': ['admin', 'user']
            }
        }
        
        # Test creation
        user = self.backend.create_user(claims)
        
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@example.com')
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)

    def test_update_user_roles(self):
        user = User.objects.create_user(username='testuser2', email='old@example.com')
        claims = {
            'preferred_username': 'testuser2',
            'email': 'new@example.com',
            'groups': ['staff']
        }
        
        # Test update
        updated_user = self.backend.update_user(user, claims)
        
        self.assertEqual(updated_user.email, 'new@example.com')
        self.assertTrue(updated_user.is_staff)
        self.assertFalse(updated_user.is_superuser)
