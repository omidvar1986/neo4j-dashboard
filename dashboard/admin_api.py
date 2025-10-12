import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging
import json
from cookie import get_cookie, get_cookie_from_input, get_cookie_from_curl_file

# Initialize logger
logger = logging.getLogger('dashboard')

class adminAPI:
    def __init__(self, base_url="https://testnetadminv2.ntx.ir", session_id=None, csrf_token=None, user_id=None):
        self.base_url = base_url
        self.session_id = session_id
        self.csrf_token = csrf_token
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
        
        # Set cookies from provided session ID and CSRF token
        if session_id:
            self._set_session_cookies(session_id, csrf_token)
        # Don't automatically load cookies - let the calling method decide

    def _set_session_cookies(self, session_id, csrf_token=None):
        """Set cookies from provided session ID and CSRF token"""
        logger.info(f"Setting session cookies - Session ID: {session_id[:20]}...")
        
        # Set session ID cookie
        self.session.cookies.set('sessionid', session_id, domain="testnetadminv2.ntx.ir", path='/')
        
        # Set CSRF token if provided
        if csrf_token:
            self.session.cookies.set('csrftoken', csrf_token, domain="testnetadminv2.ntx.ir", path='/')
            logger.info(f"Set CSRF token: {csrf_token[:20]}...")
        else:
            logger.info("No CSRF token provided - will try to extract from session")
        
        logger.info(f"Current cookies: {dict(self.session.cookies)}")

    def _get_csrf_token_from_session(self, session_id):
        """Extract CSRF token from session ID by making a GET request to accounts page"""
        try:
            logger.info(f"🔍 Extracting CSRF token from session ID: {session_id[:20]}...")
            
            # Make a GET request to the accounts page to get the CSRF token
            accounts_url = f"{self.base_url}/accounts/"
            response = self.session.get(accounts_url, allow_redirects=True)
            
            logger.info(f"Accounts page response status: {response.status_code}")
            logger.info(f"Final URL: {response.url}")
            
            if response.status_code == 200 and 'login' not in response.url:
                # Try to get CSRF token from cookies first
                csrf_token = self.session.cookies.get('csrftoken')
                if csrf_token:
                    logger.info(f"✅ Got CSRF token from cookies: {csrf_token[:20]}...")
                    return csrf_token
                
                # Try to extract from HTML
                soup = BeautifulSoup(response.text, "html.parser")
                csrf_input = soup.find("input", {"name": "csrfmiddlewaretoken"})
                if csrf_input:
                    csrf_token = csrf_input.get("value")
                    logger.info(f"✅ Got CSRF token from HTML: {csrf_token[:20]}...")
                    return csrf_token
                
                # Try to extract from script tags
                scripts = soup.find_all("script")
                for script in scripts:
                    if script.string and "csrf" in script.string.lower():
                        import re
                        csrf_match = re.search(r'["\']csrf[^"\']*["\']\s*:\s*["\']([^"\']+)["\']', script.string, re.IGNORECASE)
                        if csrf_match:
                            csrf_token = csrf_match.group(1)
                            logger.info(f"✅ Got CSRF token from script: {csrf_token[:20]}...")
                            return csrf_token
            else:
                logger.error(f"❌ Accounts page access failed: {response.status_code} or redirected to login")
                return None
            
            logger.error("❌ Could not extract CSRF token from accounts page")
            return None
            
        except Exception as e:
            logger.error(f"Error in CSRF token extraction from session ID: {e}")
            return None

    def _get_user_data_from_autocomplete_api(self, csrf_token, search_term=None, user_id=None):
        """Get user data from autocomplete API using the correct curl approach"""
        try:
            logger.info(f"🔍 Getting user data from autocomplete API...")
            
            autocomplete_url = f"{self.base_url}/accounts/fullname_email_autocomplete"
            
            # Use the provided user_id for referer, or default to accounts/ if not provided
            referer_url = f"{self.base_url}/accounts/{user_id}/user_authentication" if user_id else f"{self.base_url}/accounts/"
            
            headers = {
                'accept': '*/*',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'dnt': '1',
                'origin': 'https://testnetadminv2.ntx.ir',
                'pragma': 'no-cache',
                'priority': 'u=1, i',
                'referer': referer_url,
                'sec-ch-ua': '"Not=A?Brand";v="24", "Chromium";v="140"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"macOS"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
                'x-csrftoken': csrf_token,
                'x-requested-with': 'XMLHttpRequest'
            }
            
            # If no search term provided, try to get current user info
            if not search_term:
                # Try different search terms to find current user
                search_terms = [
                    '',  # Empty search might return current user
                    'current',
                    'me',
                    'admin',
                    'user',
                    'test',
                ]
            else:
                # Use the provided search term
                search_terms = [search_term]
            
            for term in search_terms:
                try:
                    # Use form data like the original curl
                    form_data = {
                        'term': term,
                        'q': term,
                        '_type': 'query'
                    }
                        
                    response = self.session.post(autocomplete_url, headers=headers, data=form_data)
                    logger.info(f"Autocomplete response for '{term}': {response.status_code}")
                    
                    if response.status_code == 200:
                        try:
                            result = response.json()
                            logger.info(f"Autocomplete result for '{term}': {result}")
                            
                            if 'results' in result and result['results']:
                                # Get the first result (most relevant)
                                user = result['results'][0]
                                user_data = {
                                    'uid': user.get('uid'),
                                    'email': user.get('email', ''),
                                    'full_name': user.get('full_name', ''),
                                    'id': user.get('id'),
                                    'tags': user.get('tags', [])
                                }
                                logger.info(f"✅ Found user data with search term '{term}': {user_data}")
                                return user_data
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse JSON for term '{term}': {e}")
                            continue
                except Exception as e:
                    logger.warning(f"Error with search term '{term}': {e}")
                    continue
            
            logger.error("❌ Could not get user data from autocomplete API")
            return None
            
        except Exception as e:
            logger.error(f"Error getting user data from autocomplete API: {e}")
            return None

    def _get_user_details_from_auth_page(self, user_id, csrf_token):
        """Get additional user details from the user authentication page"""
        try:
            logger.info(f"🔍 Getting additional user details for user ID: {user_id}")
            
            # Access the user authentication page
            auth_url = f"{self.base_url}/accounts/{user_id}/user_authentication"
            response = self.session.get(auth_url)
            
            logger.info(f"User authentication page status: {response.status_code}")
            
            if response.status_code == 200:
                logger.info("✅ User authentication page accessible")
                
                # Parse the HTML content
                soup = BeautifulSoup(response.text, "html.parser")
                user_data = {}
                
                # Look for user data in script tags
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.string:
                        # Look for user data patterns
                        import re
            patterns = [
                            r'"user_id":\s*"([^"]+)"',
                            r'"uid":\s*"([^"]+)"',
                            r'"email":\s*"([^"]+)"',
                            r'"full_name":\s*"([^"]+)"',
                            r'"username":\s*"([^"]+)"',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, script.string)
                if matches:
                    field_name = pattern.split('"')[1]
                    user_data[field_name] = matches[0]
                    logger.info(f"  Found {field_name}: {matches[0]}")
                
                # Check for user data in HTML elements - look for spans with user info
                user_elements = soup.find_all(['span', 'div', 'p'], class_=lambda x: x and any(keyword in x.lower() for keyword in ['user', 'email', 'name', 'info']))
                for element in user_elements:
                    text = element.get_text(strip=True)
                    if text and len(text) < 100:  # Reasonable length for user data
                        logger.info(f"  Found potential user data in HTML: {text}")
                        # Check if it looks like an email
                        if '@' in text and '.' in text:
                            user_data['email'] = text
                            logger.info(f"  Found email in HTML: {text}")
                
                # Check for input fields with user data
                inputs = soup.find_all('input', {'type': ['text', 'email', 'tel']})
                for input_field in inputs:
                    value = input_field.get('value', '')
                    name = input_field.get('name', '')
                    if value and len(value) < 100:
                        logger.info(f"  Found input field '{name}': {value}")
                        if 'email' in name.lower() and '@' in value:
                            user_data['email'] = value
                        elif 'name' in name.lower():
                            user_data['full_name'] = value
                
                # Look for specific patterns in the HTML content
                # Check for email patterns in the text
                import re
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                email_matches = re.findall(email_pattern, response.text)
                if email_matches:
                    user_data['email'] = email_matches[0]
                    logger.info(f"  Found email via regex: {email_matches[0]}")
                
                # Look for user ID in the URL or page content
                if user_id not in user_data:
                    user_data['uid'] = user_id
                
                if user_data:
                    logger.info(f"✅ Found additional user data: {user_data}")
                    return user_data
                else:
                    logger.info("ℹ️ No additional user data found on authentication page")
                    return None
            else:
                logger.error(f"❌ User authentication page not accessible: {response.status_code}")
            return None
            
        except Exception as e:
            logger.error(f"Error getting user details from auth page: {e}")
            return None

    def search_user_by_term(self, search_term):
        """Search for user by search term using autocomplete API"""
        try:
            logger.info(f"🔍 Searching for user with term: {search_term}")
            
            # Get CSRF token first
            csrf_token = self._get_csrf_token_from_session(self.session_id)
            if not csrf_token:
                logger.error("❌ Could not get CSRF token for search")
                return None
            
            # Search for user using autocomplete API
            user_data = self._get_user_data_from_autocomplete_api(csrf_token, search_term)
            
            if user_data:
                logger.info(f"✅ User found: {user_data}")
                return user_data
            else:
                logger.error(f"❌ No user found for search term: {search_term}")
                return None
            
        except Exception as e:
            logger.error(f"Error searching user by term: {e}")
            return None

    def get_user_info_from_session(self, session_id):
        """Get user information from existing session ID"""
        try:
            logger.info(f"🔍 Getting user info from session ID: {session_id[:20]}...")
            
            # Step 1: Set the provided sessionid
            self.session.cookies.set('sessionid', session_id, domain="testnetadminv2.ntx.ir", path='/')
            
            # Step 2: Get CSRF token from the session
            csrf_token = self._get_csrf_token_from_session(session_id)
            if not csrf_token:
                logger.error("❌ Could not extract CSRF token from session")
                return None
            
            # Step 3: Try to get user data from autocomplete API
            user_data = self._get_user_data_from_autocomplete_api(csrf_token)
            
            if user_data and user_data.get('uid'):
                # Step 4: Try to get additional details from user authentication page
                additional_data = self._get_user_details_from_auth_page(user_data['uid'], csrf_token)
                
                # Merge additional data if available
                if additional_data:
                    user_data.update(additional_data)
                
                # Create user info response
                user_info = {
                    'valid': True,
                    'user_id': user_data.get('uid'),
                    'email': user_data.get('email', ''),
                    'full_name': user_data.get('full_name', ''),
                    'id': user_data.get('id'),
                    'session_id': session_id,
                    'csrf_token': csrf_token,
                    'session_id_short': session_id[:20] + "..." if len(session_id) > 20 else session_id,
                    'csrf_token_short': csrf_token[:20] + "..." if csrf_token and len(csrf_token) > 20 else csrf_token,
                    'validated': True
                }
                
                logger.info(f"✅ User information retrieved:")
                logger.info(f"   User ID: {user_data.get('uid')}")
                logger.info(f"   Email: {user_data.get('email')}")
                logger.info(f"   Full Name: {user_data.get('full_name')}")
                logger.info(f"   Session ID: {session_id[:20]}...")
                logger.info(f"   CSRF Token: {csrf_token[:20]}...")
                
                return user_info
            else:
                logger.error("❌ Could not get user data from autocomplete API")
            return None
            
        except Exception as e:
            logger.error(f"Error getting user info from session: {e}")
            return None

    def validate_session_and_get_user_info(self, session_id, csrf_token, user_uid):
        """Validate session and get user information using provided UID"""
        try:
            logger.info(f"🔍 Validating session and getting user info for UID: {user_uid}")
            
            # Set both session ID and CSRF token
            self.session.cookies.set('sessionid', session_id, domain="testnetadminv2.ntx.ir", path='/')
            self.session.cookies.set('csrftoken', csrf_token, domain="testnetadminv2.ntx.ir", path='/')
            
            # Validate the session by accessing the accounts page
            logger.info("Validating session and CSRF token")
            validation_check = self.session.get(f"{self.base_url}/accounts/", allow_redirects=True)
            if 'login' in validation_check.url:
                logger.warning("⚠️ Provided session or CSRF is invalid (redirected to login).")
                return None
            
            logger.info("✅ Session and CSRF token validation successful")
            
            # Try to get additional user details from the user authentication page
            additional_data = self._get_user_details_from_auth_page(user_uid, csrf_token)
            
            # Create basic user info
            user_info = {
                'valid': True,
                'user_id': user_uid,
                'session_id': session_id,
                'csrf_token': csrf_token,
                'session_id_short': session_id[:20] + "..." if len(session_id) > 20 else session_id,
                'csrf_token_short': csrf_token[:20] + "..." if csrf_token and len(csrf_token) > 20 else csrf_token,
                'validated': True
            }
            
            # Add additional data if available
            if additional_data:
                user_info.update({
                    'email': additional_data.get('email', ''),
                    'full_name': additional_data.get('full_name', ''),
                    'id': additional_data.get('id', '')
                })
                logger.info(f"✅ Found additional user data: {additional_data}")
            else:
                logger.info("ℹ️ No additional user data found, using basic info")
            
            return user_info
            
        except Exception as e:
            logger.error(f"Error validating session and getting user info: {e}")
            return None

    def get_wallets(self, user_id):
        """Get wallets for a specific user"""
        try:
            logger.info(f"🔍 Getting wallets for user: {user_id}")
            
            # First, get the searched user's CSRF token from their user_authentication page
            user_auth_url = f"{self.base_url}/accounts/{user_id}/user_authentication"
            
            auth_headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'dnt': '1',
                'pragma': 'no-cache',
                'priority': 'u=0, i',
                'referer': f'{self.base_url}/accounts/{user_id}/add-transaction',
                'sec-ch-ua': '"Not=A?Brand";v="24", "Chromium";v="140"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"macOS"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
            }
            
            auth_response = self.session.get(user_auth_url, headers=auth_headers)
            logger.info(f"User authentication page response status: {auth_response.status_code}")
            
            if auth_response.status_code != 200:
                logger.error(f"❌ Failed to access user_authentication page: {auth_response.status_code}")
                return []
            
            # Extract the searched user's CSRF token from the user_authentication page
            soup = BeautifulSoup(auth_response.text, "html.parser")
            csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
            user_csrf_token = csrf_input.get('value') if csrf_input else None
            
            if not user_csrf_token:
                logger.error("❌ No CSRF token found on user_authentication page")
                return []
            
            logger.info(f"✅ Got searched user's CSRF token: {user_csrf_token[:20]}...")
            
            # Now use the searched user's CSRF token to access their add-transaction page
            add_transaction_url = f"{self.base_url}/accounts/{user_id}/add-transaction"
            
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'dnt': '1',
                'pragma': 'no-cache',
                'priority': 'u=0, i',
                'referer': f'{self.base_url}/accounts/{user_id}/user_authentication',
                'sec-ch-ua': '"Not=A?Brand";v="24", "Chromium";v="140"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"macOS"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
                'x-csrftoken': user_csrf_token
            }
            
            response = self.session.get(add_transaction_url, headers=headers)
            
            logger.info(f"Add transaction page response status: {response.status_code}")
            logger.info(f"Add transaction page URL: {response.url}")
            
            if response.status_code == 200:
                # Parse wallets from response
                soup = BeautifulSoup(response.text, "html.parser")
                wallets = []
                
                # Look for wallet options in select elements
                wallet_selects = soup.find_all('select', {'name': 'wallet'})
                logger.info(f"Found {len(wallet_selects)} wallet select elements")
                
                for select in wallet_selects:
                    options = select.find_all('option')
                    logger.info(f"Found {len(options)} options in select")
                    for option in options:
                        value = option.get('value', '')
                        text = option.get_text(strip=True)
                        if value and text and value != '' and value != '0':
                            wallets.append({
                                'value': value,
                                'text': text
                            })
                            logger.info(f"Added wallet: {value} - {text}")
                
                logger.info(f"✅ Found {len(wallets)} wallets for user {user_id}")
                return wallets
            else:
                logger.error(f"❌ Failed to get add-transaction page: {response.status_code}")
                logger.error(f"Response content: {response.text[:500]}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting wallets: {e}")
            return []

    def add_transaction(self, user_id, transaction_data):
        """Add a transaction for a specific user"""
        try:
            logger.info(f"🔍 Adding transaction for user: {user_id}")
            logger.info(f"Transaction data: {transaction_data}")
            
            # Get CSRF token
            csrf_token = self.session.cookies.get('csrftoken')
            if not csrf_token:
                logger.error("❌ No CSRF token available")
                return None
            
            # Prepare the transaction URL
            transaction_url = f"{self.base_url}/accounts/{user_id}/add-transaction"
            
            # Prepare headers
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'content-type': 'application/x-www-form-urlencoded',
                'dnt': '1',
                'origin': 'https://testnetadminv2.ntx.ir',
                'pragma': 'no-cache',
                'priority': 'u=0, i',
                'referer': f'{self.base_url}/accounts/{user_id}/user_authentication',
                'sec-ch-ua': '"Not=A?Brand";v="24", "Chromium";v="140"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"macOS"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
                'x-csrftoken': csrf_token
            }
            
            # Add CSRF token to transaction data
            transaction_data['csrfmiddlewaretoken'] = csrf_token
            
            # Make the POST request
            response = self.session.post(transaction_url, headers=headers, data=transaction_data)
            
            logger.info(f"Transaction response status: {response.status_code}")
            logger.info(f"Transaction response URL: {response.url}")
            
            return response
            
        except Exception as e:
            logger.error(f"Error adding transaction: {e}")
            return None

    def confirm_transaction(self, user_id, transaction_id):
        """Confirm/approve a transaction"""
        try:
            logger.info(f"🔍 Confirming transaction {transaction_id} for user: {user_id}")
            
            # Get CSRF token
            csrf_token = self.session.cookies.get('csrftoken')
            if not csrf_token:
                logger.error("❌ No CSRF token available")
                return None
            
            # Prepare the confirmation URL - based on the response analysis
            confirm_url = f"{self.base_url}/dashboard/transaction-request-accept/{transaction_id}"
            
            # Prepare headers - based on your curl example
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'dnt': '1',
                'pragma': 'no-cache',
                'priority': 'u=0, i',
                'referer': f'{self.base_url}/dashboard/{user_id}/user-transaction-request-list',
                'sec-ch-ua': '"Not=A?Brand";v="24", "Chromium";v="140"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"macOS"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
                'x-csrftoken': csrf_token
            }
            
            # Prepare data
            data = {
                'csrfmiddlewaretoken': csrf_token
            }
            
            # Make the POST request - based on your curl example
            response = self.session.post(confirm_url, headers=headers, data=data)
            
            logger.info(f"Confirmation response status: {response.status_code}")
            logger.info(f"Confirmation response URL: {response.url}")
            logger.info(f"Confirmation response content: {response.text[:500]}")
            
            return response
            
        except Exception as e:
            logger.error(f"Error confirming transaction: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None

    def get_transactions(self, user_id):
        """Get transactions for a specific user"""
        try:
            logger.info(f"🔍 Getting transactions for user: {user_id}")
            
            # Get CSRF token
            csrf_token = self.session.cookies.get('csrftoken')
            if not csrf_token:
                logger.error("❌ No CSRF token available")
                return None
            
            # Make request to get transactions
            transactions_url = f"{self.base_url}/accounts/{user_id}/transactions/"
            response = self.session.get(transactions_url)
            
            logger.info(f"Transactions response status: {response.status_code}")
            
            if response.status_code == 200:
                # Parse transactions from response
                soup = BeautifulSoup(response.text, "html.parser")
                transactions = []
                
                # Look for transaction rows in tables
                transaction_rows = soup.find_all('tr', class_=lambda x: x and 'transaction' in x.lower())
                for row in transaction_rows:
                    cells = row.find_all('td')
                    if len(cells) >= 4:  # Assuming at least 4 columns
                        transaction = {
                            'id': cells[0].get_text(strip=True) if len(cells) > 0 else '',
                            'amount': cells[1].get_text(strip=True) if len(cells) > 1 else '',
                            'wallet': cells[2].get_text(strip=True) if len(cells) > 2 else '',
                            'status': cells[3].get_text(strip=True) if len(cells) > 3 else '',
                            'created_at': cells[4].get_text(strip=True) if len(cells) > 4 else ''
                        }
                        transactions.append(transaction)
                
                logger.info(f"✅ Found {len(transactions)} transactions")
                return transactions
            else:
                logger.error(f"❌ Failed to get transactions: {response.status_code}")
                return None
            
        except Exception as e:
            logger.error(f"Error getting transactions: {e}")
            return None

    def get_feature_flags(self):
        """Get all available feature flags from the features page"""
        try:
            logger.info("🔍 Getting feature flags...")
            
            # First, get the features page to get the list of features
            features_url = f"{self.base_url}/features/feature/"
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'dnt': '1',
                'pragma': 'no-cache',
                'priority': 'u=0, i',
                'referer': f'{self.base_url}/features/feature/?from_created_at=&to_created_at=&feature=&status=&user=&search=',
                'sec-ch-ua': '"Not=A?Brand";v="24", "Chromium";v="140"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"macOS"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
            }
            
            response = self.session.get(features_url, headers=headers)
            logger.info(f"Features page response status: {response.status_code}")
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Look for feature options in select elements or similar
                feature_options = []
                
                # Try to find feature select elements
                select_elements = soup.find_all('select', {'name': 'feature'})
                for select in select_elements:
                    options = select.find_all('option')
                    for option in options:
                        value = option.get('value', '').strip()
                        text = option.get_text(strip=True)
                        if value and value != '' and text:
                            feature_options.append({
                                'value': value,
                                'text': text
                            })
                
                # If no select found, try to find feature names in other elements
                if not feature_options:
                    # Look for feature names in table rows or other elements
                    feature_elements = soup.find_all(['td', 'span', 'div'], string=lambda text: text and 'feature' in text.lower())
                    for element in feature_elements:
                        text = element.get_text(strip=True)
                        if text and len(text) > 3:  # Filter out very short text
                            feature_options.append({
                                'value': text.lower().replace(' ', '_'),
                                'text': text
                            })
                
                logger.info(f"✅ Found {len(feature_options)} feature flags")
                return feature_options
            else:
                logger.error(f"❌ Failed to get features page: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"❌ Error getting feature flags: {e}")
            return []

    def get_user_feature_flags(self, user_db_id):
        """Get existing feature flags for a specific user"""
        try:
            logger.info(f"🔍 Getting existing feature flags for user {user_db_id}")
            
            # Access the features management page with user filter
            features_url = f"{self.base_url}/features/feature/"
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'dnt': '1',
                'pragma': 'no-cache',
                'priority': 'u=0, i',
                'referer': f'{self.base_url}/',
                'sec-ch-ua': '"Not=A?Brand";v="24", "Chromium";v="140"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"macOS"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
            }
            
            # Try to filter by user - this might require a different approach
            # First, let's try to access the features page and look for user-specific data
            response = self.session.get(features_url, headers=headers)
            logger.info(f"Features page response status: {response.status_code}")
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Look for feature flags that are assigned to this user
                # This might be in a table with user information
                user_feature_flags = []
                
                # Look for table rows that contain the user ID
                table_rows = soup.find_all('tr')
                for row in table_rows:
                    row_text = row.get_text()
                    if str(user_db_id) in row_text:
                        # This row contains our user, extract feature information
                        cells = row.find_all('td')
                        if len(cells) >= 2:
                            feature_name = cells[0].get_text(strip=True)
                            if feature_name and feature_name not in ['Feature', 'Name', '']:
                                # Check if this feature is assigned to the user
                                status_cell = cells[-1] if len(cells) > 1 else None
                                status = status_cell.get_text(strip=True) if status_cell else ''
                                
                                user_feature_flags.append({
                                    'value': feature_name,
                                    'text': feature_name,
                                    'status': status,
                                    'assigned': True
                                })
                
                logger.info(f"✅ Found {len(user_feature_flags)} existing feature flags for user {user_db_id}")
                return user_feature_flags
            else:
                logger.error(f"❌ Failed to access features page: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"❌ Error getting user feature flags: {e}")
            return []

    def create_feature_flag(self, user_id, feature_name, status='done', user_db_id=None):
        """Create a feature flag for a specific user
        
        Args:
            user_id: The user UID (for logging)
            feature_name: The feature name/ID
            status: The status (done, waiting, failed)
            user_db_id: The database user ID (required for form submission)
        """
        try:
            logger.info(f"🔍 Creating feature flag for user {user_id}: {feature_name} with status {status}")
            
            # Use database user ID if provided, otherwise try to extract from user_id
            if user_db_id:
                db_user_id = str(user_db_id)
            else:
                # If user_id is already a database ID (numeric), use it
                if user_id.isdigit():
                    db_user_id = user_id
                else:
                    logger.error(f"❌ Database user ID required for feature flag creation. Got UID: {user_id}")
                    return False
            
            # First, get the create page to get CSRF token
            create_url = f"{self.base_url}/features/feature/create"
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'dnt': '1',
                'pragma': 'no-cache',
                'priority': 'u=0, i',
                'referer': f'{self.base_url}/features/feature/',
                'sec-ch-ua': '"Not=A?Brand";v="24", "Chromium";v="140"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"macOS"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
            }
            
            response = self.session.get(create_url, headers=headers)
            logger.info(f"Create page response status: {response.status_code}")
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Debug: Log all form fields found on the page
                all_inputs = soup.find_all('input')
                all_selects = soup.find_all('select')
                all_textareas = soup.find_all('textarea')
                
                logger.info(f"🔍 Found {len(all_inputs)} input fields on create page:")
                for inp in all_inputs:
                    name = inp.get('name', 'no-name')
                    input_type = inp.get('type', 'text')
                    value = inp.get('value', 'no-value')
                    logger.info(f"  - {name} ({input_type}): {value[:50]}...")
                
                logger.info(f"🔍 Found {len(all_selects)} select fields on create page:")
                for sel in all_selects:
                    name = sel.get('name', 'no-name')
                    logger.info(f"  - {name}:")
                    options = sel.find_all('option')
                    for opt in options:
                        opt_value = opt.get('value', 'no-value')
                        opt_text = opt.get_text(strip=True)
                        logger.info(f"    - {opt_value}: {opt_text}")
                
                logger.info(f"🔍 Found {len(all_textareas)} textarea fields on create page:")
                for ta in all_textareas:
                    name = ta.get('name', 'no-name')
                    logger.info(f"  - {name}")
                
                # Find CSRF token
                csrf_token = None
                csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
                if csrf_input:
                    csrf_token = csrf_input.get('value')
                    logger.info(f"Found CSRF token: {csrf_token[:20]}...")
                
                if not csrf_token:
                    logger.error("❌ No CSRF token found on create page")
                    return False
                
                # Map status values to the correct format
                status_map = {
                    'done': '1',
                    'waiting': '0', 
                    'failed': '2'
                }
                mapped_status = status_map.get(status, '1')  # Default to 'done'
                
                # Prepare form data for creating feature flag
                form_data = {
                    'csrfmiddlewaretoken': csrf_token,
                    'user': db_user_id,  # Use database user ID, not UID
                    'feature': feature_name,
                    'status': mapped_status,
                    'description': f'Feature flag created for user {user_id}',
                }
                
                # Check if there are any additional required fields by looking for hidden inputs
                hidden_inputs = soup.find_all('input', {'type': 'hidden'})
                for hidden_input in hidden_inputs:
                    name = hidden_input.get('name')
                    value = hidden_input.get('value', '')
                    if name and name not in form_data and name != 'csrfmiddlewaretoken':
                        form_data[name] = value
                        logger.info(f"🔍 Added hidden field: {name} = {value}")
                
                # Submit the form
                submit_headers = headers.copy()
                submit_headers.update({
                    'content-type': 'application/x-www-form-urlencoded',
                    'origin': self.base_url,
                })
                
                logger.info(f"🔍 Submitting form data: {form_data}")
                logger.info(f"🔍 Submit URL: {create_url}")
                logger.info(f"🔍 Mapped status: {status} -> {mapped_status}")
                
                submit_response = self.session.post(create_url, headers=submit_headers, data=form_data)
                logger.info(f"Submit response status: {submit_response.status_code}")
                
                if submit_response.status_code != 200:
                    logger.error(f"❌ Submit response content: {submit_response.text[:500]}")
                
                if submit_response.status_code in [200, 302]:
                    logger.info(f"✅ Successfully created feature flag: {feature_name} for user {user_id}")
                    return True
                else:
                    logger.error(f"❌ Failed to create feature flag: {submit_response.status_code}")
                    return False
            else:
                logger.error(f"❌ Failed to access create page: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error creating feature flag: {e}")
            return False

    def search_user_with_select2(self, search_term):
        """Search for users using the Select2 API for better name-based search"""
        try:
            logger.info(f"🔍 Searching user with Select2 API: {search_term}")
            
            # URL encode the search term
            import urllib.parse
            encoded_term = urllib.parse.quote(search_term)
            
            # The field_id seems to be a specific identifier for user search
            # We'll try to extract it from the create page first
            create_url = f"{self.base_url}/features/feature/create"
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'dnt': '1',
                'pragma': 'no-cache',
                'priority': 'u=0, i',
                'referer': f'{self.base_url}/features/feature/',
                'sec-ch-ua': '"Not=A?Brand";v="24", "Chromium";v="140"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"macOS"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
            }
            
            # First, get the create page to extract field_id
            response = self.session.get(create_url, headers=headers)
            logger.info(f"Create page response status: {response.status_code}")
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Look for Select2 field IDs in the page
                field_ids = []
                select2_elements = soup.find_all(['select', 'input'], {'class': lambda x: x and 'select2' in x.lower()})
                for element in select2_elements:
                    element_id = element.get('id', '')
                    if element_id:
                        field_ids.append(element_id)
                
                # Also look for data attributes that might contain field IDs
                data_elements = soup.find_all(attrs={'data-field-id': True})
                for element in data_elements:
                    field_id = element.get('data-field-id')
                    if field_id:
                        field_ids.append(field_id)
                
                logger.info(f"Found field IDs: {field_ids}")
                
                # Try each field ID for user search
                for field_id in field_ids:
                    try:
                        # URL encode the field_id
                        encoded_field_id = urllib.parse.quote(field_id)
                        
                        select2_url = f"{self.base_url}/select2/fields/auto.json?term={encoded_term}&field_id={encoded_field_id}"
                        
                        # Also try with the specific field_id from the user's curl example
                        if field_id == 'id_user':
                            # Use the exact field_id from the user's working curl
                            specific_field_id = "ImJiOTE3ZTE3LTM0NzEtNDhkNy04ODg2LWFhM2QyOWRlYTljMSI%3A1v5NyO%3AstqYaLtbmN3ukDrzB9fsLD9UohxCkC9xH7UxIjUupLI"
                            select2_url = f"{self.base_url}/select2/fields/auto.json?term={encoded_term}&field_id={specific_field_id}"
                        
                        select2_headers = {
                            'accept': '*/*',
                            'accept-language': 'en-US,en;q=0.9',
                            'cache-control': 'no-cache',
                            'dnt': '1',
                            'pragma': 'no-cache',
                            'priority': 'u=1, i',
                            'referer': f'{self.base_url}/features/feature/create',
                            'sec-ch-ua': '"Not=A?Brand";v="24", "Chromium";v="140"',
                            'sec-ch-ua-mobile': '?0',
                            'sec-ch-ua-platform': '"macOS"',
                            'sec-fetch-dest': 'empty',
                            'sec-fetch-mode': 'cors',
                            'sec-fetch-site': 'same-origin',
                            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
                            'x-requested-with': 'XMLHttpRequest'
                        }
                        
                        select2_response = self.session.get(select2_url, headers=select2_headers)
                        logger.info(f"Select2 response status: {select2_response.status_code}")
                        
                        if select2_response.status_code == 200:
                            try:
                                data = select2_response.json()
                                logger.info(f"Select2 result: {data}")
                                
                                if 'results' in data and data['results']:
                                    # Convert Select2 format to our standard format
                                    users = []
                                    for item in data['results']:
                                        if isinstance(item, dict):
                                            user = {
                                                'id': item.get('id'),
                                                'uid': item.get('id'),  # Select2 might use id as uid
                                                'email': item.get('text', '').split(' - ')[-1] if ' - ' in item.get('text', '') else item.get('text', ''),
                                                'full_name': item.get('text', '').split(' - ')[0] if ' - ' in item.get('text', '') else item.get('text', ''),
                                                'text': item.get('text', ''),
                                                'source': 'select2'
                                            }
                                            users.append(user)
                                    
                                    if users:
                                        logger.info(f"✅ Found {len(users)} users with Select2 API")
                                        return users[0]  # Return first match
                            except json.JSONDecodeError:
                                logger.warning(f"❌ Invalid JSON response from Select2 API")
                                continue
                    except Exception as e:
                        logger.warning(f"❌ Error with field_id {field_id}: {e}")
                        continue
            
            logger.warning(f"❌ No users found with Select2 API for: {search_term}")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error in Select2 search: {e}")
            return None

    def search_user_with_auth_page(self, search_term):
        """Search for users by accessing the user authentication page"""
        try:
            logger.info(f"🔍 Searching user with auth page method: {search_term}")
            
            # This method would require knowing user IDs to check their auth pages
            # For now, we'll return None as this is more of a verification method
            logger.info("ℹ️ Auth page search requires known user IDs - not suitable for general search")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error in auth page search: {e}")
            return None

    def comprehensive_user_search(self, search_term, current_user_id=None):
        """Comprehensive user search using multiple methods - exactly like Transaction Management"""
        try:
            logger.info(f"🔍 Comprehensive search for: {search_term}")
            
            # Get CSRF token from cookies if not set
            if not hasattr(self, 'csrf_token') or not self.csrf_token:
                self.csrf_token = self.session.cookies.get('csrftoken')
                logger.info(f"🔍 Using CSRF token from cookies: {self.csrf_token[:20] if self.csrf_token else 'None'}...")
            
            # Use the exact same approach as Transaction Management
            # The autocomplete API works well for both mobile numbers and names
            logger.info("🔍 Using autocomplete API (same as Transaction Management)...")
            user_data = self._get_user_data_from_autocomplete_api(self.csrf_token, search_term, current_user_id)
            if user_data:
                logger.info("✅ Found user with autocomplete API")
                return user_data
            
            # If not found, try some variations (but keep it simple)
            logger.info("🔍 Trying search variations...")
            variations = [
                search_term.replace(' ', ''),
                search_term.replace(' ', '_'),
                search_term.lower(),
                search_term.upper(),
            ]
            
            for variation in variations:
                if variation != search_term:  # Skip the original term
                    logger.info(f"🔍 Trying variation: {variation}")
                    user_data = self._get_user_data_from_autocomplete_api(self.csrf_token, variation, current_user_id)
                    if user_data:
                        logger.info(f"✅ Found user with variation: {variation}")
                        return user_data
            
            logger.warning(f"❌ No user found for: {search_term}")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error in comprehensive search: {e}")
            return None

    def get_multiple_users_from_autocomplete_api(self, csrf_token, search_term=None, user_id=None):
        """Get multiple users from autocomplete API - returns all matching users"""
        try:
            logger.info(f"🔍 Getting multiple users from autocomplete API for: {search_term}")
            
            autocomplete_url = f"{self.base_url}/accounts/fullname_email_autocomplete"
            
            # Use the provided user_id for referer, or default to accounts/ if not provided
            referer_url = f"{self.base_url}/accounts/{user_id}/user_authentication" if user_id else f"{self.base_url}/accounts/"
            
            headers = {
                'accept': '*/*',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'dnt': '1',
                'origin': 'https://testnetadminv2.ntx.ir',
                'pragma': 'no-cache',
                'priority': 'u=1, i',
                'referer': referer_url,
                'sec-ch-ua': '"Not=A?Brand";v="24", "Chromium";v="140"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"macOS"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
                'x-csrftoken': csrf_token,
                'x-requested-with': 'XMLHttpRequest'
            }
            
            # Prepare form data
            form_data = {
                'term': search_term,
                'q': search_term,
                '_type': 'query'
            }
                
            response = self.session.post(autocomplete_url, headers=headers, data=form_data)
            logger.info(f"Autocomplete response: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    logger.info(f"Autocomplete result: {result}")
                    
                    if 'results' in result and result['results']:
                        # Convert all results to our standard format
                        users = []
                        for user in result['results']:
                            user_data = {
                                'uid': user.get('uid'),
                                'email': user.get('email', ''),
                                'full_name': user.get('full_name', ''),
                                'id': user.get('id'),
                                'user_id': user.get('uid'),  # Add user_id for consistency
                                'tags': user.get('tags', [])
                            }
                            users.append(user_data)
                        
                        logger.info(f"✅ Found {len(users)} users with autocomplete API")
                        return users
                    else:
                        logger.info("No results found in autocomplete API")
                        return []
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse JSON: {e}")
                    return []
            else:
                logger.error(f"Autocomplete API error: {response.status_code}")
                return []
            
        except Exception as e:
            logger.error(f"Error getting multiple users from autocomplete API: {e}")
            return []

    def get_last_otp_messages(self, limit=20):
        """Get the last OTP messages from the admin panel"""
        try:
            url = f"{self.base_url}/admin/accounts/usersms/"
            response = self.session.get(url)
            
            if response.status_code == 200:
                # Parse the HTML response to extract OTP messages
                soup = BeautifulSoup(response.text, 'html.parser')
                otp_messages = []
                
                # Find all tables on the page
                tables = soup.find_all('table')
                
                # Look for the main data table (usually the largest one)
                main_table = None
                max_rows = 0
                
                for table in tables:
                    rows = table.find_all('tr')
                    if len(rows) > max_rows:
                        max_rows = len(rows)
                        main_table = table
                
                if main_table:
                    # Get all rows (including header)
                    all_rows = main_table.find_all('tr')
                    
                    # Skip header row and process data rows
                    for i, row in enumerate(all_rows[1:], 1):
                        if i > limit:
                            break
                            
                        cells = row.find_all(['td', 'th'])
                        
                        if len(cells) >= 6:  # At least 6 columns
                            # Extract data from each column (PK is in cell 1, not 0)
                            pk = cells[1].get_text(strip=True) if len(cells) > 1 else ''
                            created_at = cells[2].get_text(strip=True) if len(cells) > 2 else ''
                            to_phone = cells[3].get_text(strip=True) if len(cells) > 3 else ''
                            user = cells[4].get_text(strip=True) if len(cells) > 4 else ''
                            tp = cells[5].get_text(strip=True) if len(cells) > 5 else ''
                            text = cells[6].get_text(strip=True) if len(cells) > 6 else ''
                            details = cells[7].get_text(strip=True) if len(cells) > 7 else ''
                            
                            # Only add if we have meaningful data (PK and at least text or user)
                            if pk and (text or user or to_phone):
                                otp_messages.append({
                                    'pk': pk,
                                    'created_at': created_at,
                                    'to': to_phone,
                                    'user': user,
                                    'tp': tp,
                                    'text': text,
                                    'details': details
                                })
                else:
                    logger.error("❌ No suitable table found on the page")
                
                logger.info(f"✅ Found {len(otp_messages)} OTP messages")
                return otp_messages
            else:
                logger.error(f"❌ Failed to get OTP messages: {response.status_code}")
                logger.error(f"Response content: {response.text[:500]}")
                return []
                
        except Exception as e:
            logger.error(f"❌ Error getting OTP messages: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return []

    def get_restriction_page(self, user_id):
        """Get the restriction page for a specific user to extract form data"""
        try:
            logger.info(f"🔍 Getting restriction page for user: {user_id}")
            
            url = f"{self.base_url}/accounts/{user_id}/restriction"
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'dnt': '1',
                'pragma': 'no-cache',
                'priority': 'u=0, i',
                'referer': f'{self.base_url}/accounts/{user_id}/user_authentication',
                'sec-ch-ua': '"Chromium";v="141", "Not?A_Brand";v="8"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"macOS"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'
            }
            
            response = self.session.get(url, headers=headers)
            logger.info(f"Restriction page response status: {response.status_code}")
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract form data
                form_data = {}
                
                # Get CSRF token
                csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
                if csrf_input:
                    form_data['csrf_token'] = csrf_input.get('value')
                    logger.info(f"✅ Found CSRF token: {form_data['csrf_token'][:20]}...")
                
                # Get available currencies
                currencies = []
                currency_select = soup.find('select', {'name': 'currency'})
                if currency_select:
                    options = currency_select.find_all('option')
                    for option in options:
                        value = option.get('value', '')
                        text = option.get_text(strip=True)
                        if value and value != '0':
                            currencies.append({
                                'value': value,
                                'text': text
                            })
                
                logger.info(f"✅ Found {len(currencies)} currencies")
                return {
                    'success': True,
                    'csrf_token': form_data.get('csrf_token'),
                    'currencies': currencies
                }
            else:
                logger.error(f"❌ Failed to get restriction page: {response.status_code}")
                return {'success': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            logger.error(f"❌ Error getting restriction page: {e}")
            return {'success': False, 'error': str(e)}

    def create_withdrawal_permission(self, user_id, amount_limit=1000000000, description="بلا", 
                                   currency="0", all_currencies=False, effective_time_day=26, 
                                   effective_time_month=7, effective_time_year=1404):
        """Create withdrawal permission for a user"""
        try:
            logger.info(f"🔍 Creating withdrawal permission for user: {user_id}")
            logger.info(f"Amount limit: {amount_limit}, Currency: {currency}, All currencies: {all_currencies}")
            
            # First get the restriction page to get CSRF token
            page_data = self.get_restriction_page(user_id)
            if not page_data['success']:
                return {'success': False, 'error': f"Failed to get restriction page: {page_data['error']}"}
            
            csrf_token = page_data['csrf_token']
            if not csrf_token:
                return {'success': False, 'error': 'No CSRF token found'}
            
            # Prepare form data
            form_data = {
                'csrfmiddlewaretoken': csrf_token,
                'effective_time_day': str(effective_time_day),
                'effective_time_month': str(effective_time_month),
                'effective_time_year': str(effective_time_year),
                'currency': currency,
                'amount_limit': str(amount_limit),
                'consideration': description,
                'type': 'withdraw_request_permit'
            }
            
            # Add all_currencies if selected
            if all_currencies:
                form_data['all_currencies'] = 'all_currencies'
            
            # Submit the form
            url = f"{self.base_url}/accounts/{user_id}/restriction"
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'content-type': 'application/x-www-form-urlencoded',
                'dnt': '1',
                'origin': self.base_url,
                'pragma': 'no-cache',
                'priority': 'u=0, i',
                'referer': f'{self.base_url}/accounts/{user_id}/restriction',
                'sec-ch-ua': '"Chromium";v="141", "Not?A_Brand";v="8"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"macOS"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36'
            }
            
            logger.info(f"🔍 Submitting withdrawal permission form...")
            response = self.session.post(url, headers=headers, data=form_data)
            logger.info(f"Withdrawal permission response status: {response.status_code}")
            
            if response.status_code in [200, 302]:
                logger.info(f"✅ Successfully created withdrawal permission for user {user_id}")
                return {
                    'success': True,
                    'message': f'Withdrawal permission created successfully with limit {amount_limit:,} tomans'
                }
            else:
                logger.error(f"❌ Failed to create withdrawal permission: {response.status_code}")
                return {'success': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            logger.error(f"❌ Error creating withdrawal permission: {e}")
            return {'success': False, 'error': str(e)}