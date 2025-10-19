import json
import os


class WireMockEnv:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    @staticmethod
    def get_wiremock_config():
        """Load WireMock configuration from environment or config file"""
        # Try to load from environment variables first
        try:
            return WireMockEnv(
                JIBIT_COBANK_SECRET_KEY=os.getenv('JIBIT_COBANK_SECRET_KEY', ''),
                TOMAN_COBANK_FIXED_ACCESS_TOKEN=os.getenv('TOMAN_COBANK_FIXED_ACCESS_TOKEN', ''),
                TOMAN_COBANK_CLIENT_ID=os.getenv('TOMAN_COBANK_CLIENT_ID', ''),
                TOMAN_COBANK_CLIENT_SECRET=os.getenv('TOMAN_COBANK_CLIENT_SECRET', ''),
                TTXCONVERT_PATH=os.getenv('TTXCONVERT_PATH', ''),
                JIBIT_COBANK_FIXED_ACCESS_TOKEN=os.getenv('JIBIT_COBANK_FIXED_ACCESS_TOKEN', ''),
                JIBIT_COBANK_FIXED_REFRESH_TOKEN=os.getenv('JIBIT_COBANK_FIXED_REFRESH_TOKEN', ''),
                JIBIT_COBANK_PATH=os.getenv('JIBIT_COBANK_PATH', ''),
                WIREMOCK_BASEURL=os.getenv('WIREMOCK_BASEURL', 'https://wiremock.ntx.ir'),
                TOMAN_COBANK_PATH=os.getenv('TOMAN_COBANK_PATH', ''),
                NOBITEX_TESTNET_BASEURL=os.getenv('NOBITEX_TESTNET_BASEURL', ''),
                NOBITEX_TESTNET_ACCESS_TOKEN=os.getenv('NOBITEX_TESTNET_ACCESS_TOKEN', ''),
                JIBIT_COBANK_API_KEY=os.getenv('JIBIT_COBANK_API_KEY', ''),
                TOMAN_COBANK_USERNAME=os.getenv('TOMAN_COBANK_USERNAME', ''),
                TOMAN_COBANK_PASSWORD=os.getenv('TOMAN_COBANK_PASSWORD', ''),
                TOMAN_COBANK_FIXED_REFRESH_TOKEN=os.getenv('TOMAN_COBANK_FIXED_REFRESH_TOKEN', ''),
                WIREMOCK_ADMIN_PASSWORD=os.getenv('WIREMOCK_ADMIN_PASSWORD', 'n9d8c2398ncnuic23y9pYIfbtobfco23vt8bc823btoiTYUTU'),
                WIREMOCK_ADMIN_USERNAME=os.getenv('WIREMOCK_ADMIN_USERNAME', 'nobitex'),
                PAYMAN_DIRECT_DEBIT_PATH=os.getenv('PAYMAN_DIRECT_DEBIT_PATH', ''),
                PAYMAN_DIRECT_DEBIT_CLIENTID=os.getenv('PAYMAN_DIRECT_DEBIT_CLIENTID', ''),
                PAYMAN_DIRECT_DEBIT_CLIENT_SECRET=os.getenv('PAYMAN_DIRECT_DEBIT_CLIENT_SECRET', ''),
                PAYMAN_DIRECT_DEBIT_FIXED_ACCESS_TOKEN=os.getenv('PAYMAN_DIRECT_DEBIT_FIXED_ACCESS_TOKEN', ''),
                JIBIT_IDE_API_KEY=os.getenv('JIBIT_IDE_API_KEY', ''),
                JIBIT_IDE_SECRET_KEY=os.getenv('JIBIT_IDE_SECRET_KEY', ''),
                JIBIT_IDE_FIXED_ACCESS_TOKEN=os.getenv('JIBIT_IDE_FIXED_ACCESS_TOKEN', ''),
                JIBIT_IDE_FIXED_REFRESH_TOKEN=os.getenv('JIBIT_IDE_FIXED_REFRESH_TOKEN', ''),
                JIBIT_IDE_PATH=os.getenv('JIBIT_IDE_PATH', ''),
                JIBIT_TRF_PATH=os.getenv('JIBIT_TRF_PATH', ''),
                JIBIT_TRF_API_KEY=os.getenv('JIBIT_TRF_API_KEY', ''),
                JIBIT_TRF_SECRET_KEY=os.getenv('JIBIT_TRF_SECRET_KEY', ''),
                JIBIT_TRF_FIXED_ACCESS_TOKEN=os.getenv('JIBIT_TRF_FIXED_ACCESS_TOKEN', ''),
                JIBIT_TRF_FIXED_REFRESH_TOKEN=os.getenv('JIBIT_TRF_FIXED_REFRESH_TOKEN', ''),
            )
        except Exception:
            pass
        
        # Fallback to config file
        config_file_path = os.path.join(os.path.dirname(__file__), '..', 'wiremock_config.json')
        if os.path.exists(config_file_path):
            try:
                with open(config_file_path, 'r') as file:
                    config_data = json.load(file)
                return WireMockEnv(**config_data)
            except (Exception, json.JSONDecodeError) as e:
                print(f"Warning: Could not load config file: {e}")
        
        # Final fallback with default values - NO HARDCODED CREDENTIALS
        return WireMockEnv(
            JIBIT_COBANK_SECRET_KEY='',
            TOMAN_COBANK_FIXED_ACCESS_TOKEN='',
            TOMAN_COBANK_CLIENT_ID='',
            TOMAN_COBANK_CLIENT_SECRET='',
            TTXCONVERT_PATH='',
            JIBIT_COBANK_FIXED_ACCESS_TOKEN='',
            JIBIT_COBANK_FIXED_REFRESH_TOKEN='',
            JIBIT_COBANK_PATH='',
            WIREMOCK_BASEURL='',
            TOMAN_COBANK_PATH='',
            NOBITEX_TESTNET_BASEURL='',
            NOBITEX_TESTNET_ACCESS_TOKEN='',
            JIBIT_COBANK_API_KEY='',
            TOMAN_COBANK_USERNAME='',
            TOMAN_COBANK_PASSWORD='',
            TOMAN_COBANK_FIXED_REFRESH_TOKEN='',
            WIREMOCK_ADMIN_PASSWORD='',
            WIREMOCK_ADMIN_USERNAME='',
            PAYMAN_DIRECT_DEBIT_PATH='',
            PAYMAN_DIRECT_DEBIT_CLIENTID='',
            PAYMAN_DIRECT_DEBIT_CLIENT_SECRET='',
            PAYMAN_DIRECT_DEBIT_FIXED_ACCESS_TOKEN='',
            JIBIT_IDE_API_KEY='',
            JIBIT_IDE_SECRET_KEY='',
            JIBIT_IDE_FIXED_ACCESS_TOKEN='',
            JIBIT_IDE_FIXED_REFRESH_TOKEN='',
            JIBIT_IDE_PATH='',
            JIBIT_TRF_PATH='',
            JIBIT_TRF_API_KEY='',
            JIBIT_TRF_SECRET_KEY='',
            JIBIT_TRF_FIXED_ACCESS_TOKEN='',
            JIBIT_TRF_FIXED_REFRESH_TOKEN='',
        )
