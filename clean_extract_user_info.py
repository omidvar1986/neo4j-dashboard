"""
Clean implementation of dynamic user data extraction
"""

def extract_user_info_from_session_clean(self, expected_user_id=None):
    """Extract user information dynamically from session ID"""
    try:
        sessionid = self.session.cookies.get('sessionid')
        
        if not sessionid:
            logger.error("No session ID found in cookies")
            return {'valid': False, 'error': 'No session ID found'}
        
        logger.info(f"🔍 Dynamically extracting user info for session: {sessionid[:20]}...")
        
        # Use dynamic extraction method
        user_data = self._extract_user_data_dynamically(sessionid)
        if not user_data:
            logger.error("Could not extract user data dynamically")
            return {'valid': False, 'error': 'Could not extract user data'}
        
        # Create user_info with dynamically extracted data
        user_info = {
            'valid': True,
            'user_id': user_data['user_id'],
            'sessionid': user_data['sessionid'],
            'csrftoken': user_data['csrf_token'],
            'username': None,
            'phone_number': None,
            'email': None,
            'validated': True
        }
        
        # Store for future use
        self._store_user_id_for_session(sessionid, user_data['user_id'])
        logger.info(f"✅ Dynamic user extraction successful - User ID: {user_data['user_id']}")
        return user_info
        
    except Exception as e:
        logger.error(f"Error in extract_user_info_from_session: {e}")
        return {'valid': False, 'error': str(e)}

def _extract_user_data_dynamically_clean(self, sessionid):
    """Dynamically extract user data from session ID by making requests to the admin panel"""
    try:
        logger.info(f"🔍 Dynamically extracting user data for session: {sessionid[:20]}...")
        
        # Step 1: Get CSRF token by visiting a page
        csrf_token = self._get_dynamic_csrf_token(sessionid)
        if not csrf_token:
            logger.error("Could not get CSRF token")
            return None
        
        # Step 2: Try to get user ID from the dashboard or user-specific pages
        user_id = self._extract_user_id_from_dashboard(sessionid)
        if not user_id:
            logger.error("Could not extract user ID from dashboard")
            return None
        
        logger.info(f"✅ Successfully extracted user data - User ID: {user_id}")
        
        return {
            'user_id': user_id,
            'csrf_token': csrf_token,
            'sessionid': sessionid
        }
        
    except Exception as e:
        logger.error(f"Error in dynamic user data extraction: {e}")
        return None

def _get_dynamic_csrf_token_clean(self, sessionid):
    """Get CSRF token dynamically from the admin panel"""
    try:
        # Try multiple endpoints to get CSRF token
        endpoints = [
            f"{self.base_url}/dashboard/",
            f"{self.base_url}/accounts/",
            f"{self.base_url}/",
        ]
        
        for endpoint in endpoints:
            try:
                logger.info(f"🔍 Trying to get CSRF token from: {endpoint}")
                response = self.session.get(endpoint, allow_redirects=True)
                
                if response.status_code == 200 and 'login' not in response.url:
                    # Try to get CSRF token from cookies first
                    csrf_token = self.session.cookies.get('csrftoken')
                    if csrf_token:
                        logger.info(f"✅ Got CSRF token from cookies: {csrf_token[:20]}...")
                        return csrf_token
                    
                    # If not in cookies, try HTML parsing
                    soup = BeautifulSoup(response.text, "html.parser")
                    
                    # Look for CSRF token in script tags
                    script_tags = soup.find_all("script")
                    for script in script_tags:
                        if script.string and "CSRF_TOKEN" in script.string:
                            import re
                            csrf_match = re.search(r'CSRF_TOKEN\s*=\s*["\']([^"\']+)["\']', script.string)
                            if csrf_match:
                                csrf_token = csrf_match.group(1)
                                logger.info(f"✅ Got CSRF token from script: {csrf_token[:20]}...")
                                # Store in cookies
                                self.session.cookies.set('csrftoken', csrf_token, domain="testnetadminv2.ntx.ir", path='/')
                                return csrf_token
                    
                    # Try input field
                    csrf_tag = soup.find("input", {"name": "csrfmiddlewaretoken"})
                    if csrf_tag:
                        csrf_token = csrf_tag.get("value")
                        if csrf_token:
                            logger.info(f"✅ Got CSRF token from input: {csrf_token[:20]}...")
                            self.session.cookies.set('csrftoken', csrf_token, domain="testnetadminv2.ntx.ir", path='/')
                            return csrf_token
                
            except Exception as e:
                logger.warning(f"Error getting CSRF token from {endpoint}: {e}")
                continue
        
        logger.error("Could not get CSRF token from any endpoint")
        return None
        
    except Exception as e:
        logger.error(f"Error in dynamic CSRF token extraction: {e}")
        return None

def _extract_user_id_from_dashboard_clean(self, sessionid):
    """Extract user ID from dashboard pages"""
    try:
        # Try to get user ID from dashboard pages
        dashboard_endpoints = [
            f"{self.base_url}/dashboard/",
            f"{self.base_url}/accounts/",
        ]
        
        for endpoint in dashboard_endpoints:
            try:
                logger.info(f"🔍 Trying to extract user ID from: {endpoint}")
                response = self.session.get(endpoint, allow_redirects=True)
                
                if response.status_code == 200 and 'login' not in response.url:
                    # Look for user ID patterns in the page content
                    user_id = self._find_user_id_in_content(response.text)
                    if user_id:
                        logger.info(f"✅ Found user ID in {endpoint}: {user_id}")
                        return user_id
                
            except Exception as e:
                logger.warning(f"Error extracting user ID from {endpoint}: {e}")
                continue
        
        # If not found in dashboard, try autocomplete
        logger.info("🔍 Trying autocomplete method...")
        return self._extract_current_user_id_from_autocomplete(sessionid)
        
    except Exception as e:
        logger.error(f"Error in user ID extraction from dashboard: {e}")
        return None

def _find_user_id_in_content_clean(self, content):
    """Find user ID patterns in page content"""
    try:
        import re
        
        # Common user ID patterns
        patterns = [
            r'/dashboard/([a-f0-9-]{32})/',  # /dashboard/{user_id}/
            r'/accounts/([a-f0-9-]{32})/',  # /accounts/{user_id}/
            r'user_id["\']?\s*[:=]\s*["\']([a-f0-9-]{32})["\']',  # user_id: "abc123"
            r'data-user-id=["\']([a-f0-9-]{32})["\']',  # data-user-id attribute
            r'id=["\']user_id["\'].*?value=["\']([a-f0-9-]+)["\']',  # id="user_id" input
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                user_id = match.group(1)
                if len(user_id) >= 20:  # Valid user ID should be long enough
                    logger.info(f"✅ Found user ID using pattern '{pattern}': {user_id}")
                    return user_id
        
        return None
        
    except Exception as e:
        logger.error(f"Error finding user ID in content: {e}")
        return None
