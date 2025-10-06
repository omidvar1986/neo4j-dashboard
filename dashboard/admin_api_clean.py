import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging
from cookie import get_cookie, get_cookie_from_input, get_cookie_from_curl_file

# Initialize logger
logger = logging.getLogger('dashboard')

class adminAPI:
    def __init__(self, base_url="https://testnetadminv2.ntx.ir", user_token=None, user_id=None):
        self.base_url = base_url
        self.user_token = user_token
        self.user_id = user_id
        self.session = requests.Session()
        self.session.headers.update({
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
            'cache-control': 'max-age=0',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://testnetadminv2.ntx.ir',
            'priority': 'u=0, i',
            'referer': 'https://testnetadminv2.ntx.ir/',
            'sec-ch-ua': '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
        })
        if user_token:
            self._set_user_token()
        else:
            self._set_cookies()

    def _set_cookies(self, fetch_token=None):
        """Set cookies from input or fallback to get_cookie()"""
        if fetch_token:
            logger.info(f"Getting cookies from input: {fetch_token[:50]}...")
            if '=' in fetch_token:
                cookies = [c.strip() for c in fetch_token.split(';') if c.strip()]
            else:
                # Only set sessionid, CSRF token will be fetched dynamically
                cookies = [f"sessionid={fetch_token}"]
        else:
            logger.info("No input token, trying default sources...")
            cookies = get_cookie()
        
        # Set cookies in session
        for cookie in cookies:
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                self.session.cookies.set(name.strip(), value.strip(), domain="testnetadminv2.ntx.ir", path='/')
        
        # Note: CSRF token will be fetched dynamically when making requests
        logger.info("ℹ️ CSRF token will be fetched dynamically from the target page")

    def _set_user_token(self):
        """Set user token for authentication"""
        if self.user_token:
            self.session.headers['Authorization'] = f'Bearer {self.user_token}'

    def extract_user_info_from_session(self, expected_user_id=None):
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
            
            logger.info(f"✅ Dynamic user extraction successful - User ID: {user_data['user_id']}")
            return user_info
            
        except Exception as e:
            logger.error(f"Error in extract_user_info_from_session: {e}")
            return {'valid': False, 'error': str(e)}

    def _extract_user_data_dynamically(self, sessionid):
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

    def _get_dynamic_csrf_token(self, sessionid):
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

    def _extract_user_id_from_dashboard(self, sessionid):
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
            
            logger.error("Could not extract user ID from any page")
            return None
            
        except Exception as e:
            logger.error(f"Error in user ID extraction from dashboard: {e}")
            return None

    def _find_user_id_in_content(self, content):
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

    def validate_token(self):
        """Validate the current token and return user information"""
        return self.extract_user_info_from_session()

    def get(self, endpoint, **kwargs):
        url = urljoin(self.base_url, endpoint)
        return self.session.get(url, **kwargs)

    def post(self, endpoint, data=None, json=None, **kwargs):
        url = urljoin(self.base_url, endpoint)

        # 1) Ensure sessionid cookie is already set in self.session.cookies
        # 2) GET the exact page you will POST to — this allows the server to set the csrftoken cookie
        get_resp = self.session.get(url, allow_redirects=True)

        # If GET was redirected to login, sessionid might be invalid
        if get_resp.history or 'login' in get_resp.url:
            logger.warning("GET to %s redirected to login (session may be invalid). final url: %s", url, get_resp.url)

        # 3) Get CSRF token dynamically from the specific page
        csrf_token = None
        
        # First try to get from cookies (if server set it)
        csrf_token = self.session.cookies.get('csrftoken')
        print(f"🔍 CSRF Token from cookies: {csrf_token}")
        
        # If no CSRF token in cookies, get it from the HTML page
        if not csrf_token:
            print("🔍 No CSRF token in cookies, getting from HTML page...")
            soup = BeautifulSoup(get_resp.text, "html.parser")
            
            # Try multiple methods to find CSRF token
            csrf_tag = soup.find("input", {"name": "csrfmiddlewaretoken"})
            if csrf_tag:
                csrf_token = csrf_tag.get("value")
                print(f"🔍 CSRF Token from HTML input: {csrf_token}")
            else:
                # Try to find in script tags
                script_tags = soup.find_all("script")
                for script in script_tags:
                    if script.string and "CSRF_TOKEN" in script.string:
                        import re
                        csrf_match = re.search(r'CSRF_TOKEN\s*=\s*["\']([^"\']+)["\']', script.string)
                        if csrf_match:
                            csrf_token = csrf_match.group(1)
                            print(f"🔍 CSRF Token from script: {csrf_token}")
                            break
                
                if not csrf_token:
                    print("🔍 No CSRF token found in HTML either")
        
        # Store the CSRF token in cookies for future use
        if csrf_token:
            self.session.cookies.set('csrftoken', csrf_token, domain="testnetadminv2.ntx.ir", path='/')
            print(f"🔍 Stored CSRF token in cookies: {csrf_token}")

        if not csrf_token:
            raise RuntimeError("No CSRF token found after GET. Check sessionid, redirects, and GET response content.")

        logger.info(f"✅ Got CSRF token: {csrf_token[:20]}...")

        # 5) Set headers and POST
        headers = kwargs.pop('headers', {})
        headers.update({
            'X-CSRFToken': csrf_token,
            'Referer': url,  # Django's CSRF checks require a matching Referer for secure sites
        })

        # Prepare payload
        if data is not None:
            if isinstance(data, dict):
                data = {**{"csrfmiddlewaretoken": csrf_token}, **data}
            elif isinstance(data, str):
                data = f"csrfmiddlewaretoken={csrf_token}&" + data
        elif json is not None:
            json = {**{"csrfmiddlewaretoken": csrf_token}, **json}
        else:
            data = {"csrfmiddlewaretoken": csrf_token}

        return self.session.post(url, data=data, json=json, headers=headers, **kwargs)

    def add_transaction(self, user_id, transaction_data):
        """Add a transaction for a specific user"""
        endpoint = f"accounts/{user_id}/add-transaction"
        return self.post(endpoint, data=transaction_data)

    def get_wallets(self, user_id):
        """Get available wallets for a user"""
        endpoint = f"accounts/{user_id}/wallets"
        return self.get(endpoint)

    def search_user_by_contact(self, phone_or_email):
        """Search for user by phone or email"""
        endpoint = "accounts/search"
        data = {"contact": phone_or_email}
        return self.post(endpoint, data=data)

    def get_user_transactions(self, user_id):
        """Get user transaction requests list"""
        endpoint = f"accounts/{user_id}/transactions"
        return self.get(endpoint)

    def confirm_transaction(self, user_id, transaction_id):
        """Confirm a transaction"""
        endpoint = f"accounts/{user_id}/transactions/{transaction_id}/confirm"
        return self.post(endpoint)

    def reject_transaction(self, user_id, transaction_id):
        """Reject a transaction"""
        endpoint = f"accounts/{user_id}/transactions/{transaction_id}/reject"
        return self.post(endpoint)

    def edit_transaction(self, user_id, transaction_id, transaction_data):
        """Edit a transaction"""
        endpoint = f"accounts/{user_id}/transactions/{transaction_id}/edit"
        return self.post(endpoint, data=transaction_data)
