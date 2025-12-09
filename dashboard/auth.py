import logging
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from django.conf import settings

logger = logging.getLogger('dashboard')

class KeycloakOIDCBackend(OIDCAuthenticationBackend):
    def get_username(self, claims):
        """Return username from specific claim."""
        # Use existing setting for claim name, default to preferred_username
        return claims.get('preferred_username')

    def create_user(self, claims):
        """Return object for a newly created user account."""
        user = super(KeycloakOIDCBackend, self).create_user(claims)
        
        # Update user based on claims
        self.update_user(user, claims)
        
        return user

    def update_user(self, user, claims):
        """Update existing user with new claims, if necessary save, and return user"""
        
        # Default behavior: update email, first_name, last_name
        user.email = claims.get('email', '')
        user.first_name = claims.get('given_name', '')
        user.last_name = claims.get('family_name', '')
        
        # Role/Group Mapping
        # Keycloak usually sends roles in 'realm_access.roles' or 'resource_access.<client_id>.roles'
        # or sometimes in a flat 'groups' claim depending on mapper configuration.
        
        roles = claims.get('realm_access', {}).get('roles', [])
        groups = claims.get('groups', [])
        
        # Combine all potential sources of roles
        all_roles = set(roles)
        if isinstance(groups, list):
            all_roles.update(groups)
            
        logger.info(f"OIDC: User {user.username} has roles/groups: {all_roles}")

        # Map to Django is_superuser
        superuser_role = getattr(settings, 'KEYCLOAK_SUPERUSER_ROLE', 'admin')
        if superuser_role in all_roles:
            user.is_superuser = True
            user.is_staff = True
            user.save()
            logger.info(f"OIDC: User {user.username} granted superuser access")
            
        # Map to Django is_staff
        staff_role = getattr(settings, 'KEYCLOAK_STAFF_ROLE', 'staff')
        if staff_role in all_roles:
            user.is_staff = True
            user.save()
            logger.info(f"OIDC: User {user.username} granted staff access")

        return user

    def filter_users_by_claims(self, claims):
        """Return list of users matching the claims."""
        username = claims.get('preferred_username')
        if not username:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(username__iexact=username)
