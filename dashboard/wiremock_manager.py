import json
import os
import base64
from typing import List

from requests import request
from wiremock.client import (
    Mappings,
    Mapping,
    MappingRequest,
    MappingResponse,
    HttpMethods,
    NotFoundException,
    Requests,
)
from wiremock.constants import Config
from pydantic import BaseModel, ValidationError
from .utils.file_manager import (
    safe_read_and_append,
    read_file,
    clear_file,
    clear_and_write_file,
)


class WireMockEnv(BaseModel):
    JIBIT_COBANK_SECRET_KEY: str
    TOMAN_COBANK_FIXED_ACCESS_TOKEN: str
    TOMAN_COBANK_CLIENT_ID: str
    TOMAN_COBANK_CLIENT_SECRET: str
    TTXCONVERT_PATH: str
    JIBIT_COBANK_FIXED_ACCESS_TOKEN: str
    JIBIT_COBANK_FIXED_REFRESH_TOKEN: str
    JIBIT_COBANK_PATH: str
    WIREMOCK_BASEURL: str
    TOMAN_COBANK_PATH: str
    NOBITEX_TESTNET_BASEURL: str
    NOBITEX_TESTNET_ACCESS_TOKEN: str
    JIBIT_COBANK_API_KEY: str
    TOMAN_COBANK_USERNAME: str
    TOMAN_COBANK_PASSWORD: str
    TOMAN_COBANK_FIXED_REFRESH_TOKEN: str
    WIREMOCK_ADMIN_PASSWORD: str
    WIREMOCK_ADMIN_USERNAME: str
    PAYMAN_DIRECT_DEBIT_PATH: str
    PAYMAN_DIRECT_DEBIT_CLIENTID: str
    PAYMAN_DIRECT_DEBIT_CLIENT_SECRET: str
    PAYMAN_DIRECT_DEBIT_FIXED_ACCESS_TOKEN: str
    JIBIT_IDE_API_KEY: str
    JIBIT_IDE_SECRET_KEY: str
    JIBIT_IDE_FIXED_ACCESS_TOKEN: str
    JIBIT_IDE_FIXED_REFRESH_TOKEN: str
    JIBIT_IDE_PATH: str
    JIBIT_TRF_PATH: str
    JIBIT_TRF_API_KEY: str
    JIBIT_TRF_SECRET_KEY: str
    JIBIT_TRF_FIXED_ACCESS_TOKEN: str
    JIBIT_TRF_FIXED_REFRESH_TOKEN: str

    @staticmethod
    def get_wiremock_config():
        # Try to load from environment variables first
        try:
            config = WireMockEnv(
                JIBIT_COBANK_SECRET_KEY=os.getenv('JIBIT_COBANK_SECRET_KEY', ''),
                TOMAN_COBANK_FIXED_ACCESS_TOKEN=os.getenv('TOMAN_COBANK_FIXED_ACCESS_TOKEN', ''),
                TOMAN_COBANK_CLIENT_ID=os.getenv('TOMAN_COBANK_CLIENT_ID', ''),
                TOMAN_COBANK_CLIENT_SECRET=os.getenv('TOMAN_COBANK_CLIENT_SECRET', ''),
                TTXCONVERT_PATH=os.getenv('TTXCONVERT_PATH', ''),
                JIBIT_COBANK_FIXED_ACCESS_TOKEN=os.getenv('JIBIT_COBANK_FIXED_ACCESS_TOKEN', ''),
                JIBIT_COBANK_FIXED_REFRESH_TOKEN=os.getenv('JIBIT_COBANK_FIXED_REFRESH_TOKEN', ''),
                JIBIT_COBANK_PATH=os.getenv('JIBIT_COBANK_PATH', ''),
                WIREMOCK_BASEURL=os.getenv('WIREMOCK_BASEURL', ''),
                TOMAN_COBANK_PATH=os.getenv('TOMAN_COBANK_PATH', ''),
                NOBITEX_TESTNET_BASEURL=os.getenv('NOBITEX_TESTNET_BASEURL', ''),
                NOBITEX_TESTNET_ACCESS_TOKEN=os.getenv('NOBITEX_TESTNET_ACCESS_TOKEN', ''),
                JIBIT_COBANK_API_KEY=os.getenv('JIBIT_COBANK_API_KEY', ''),
                TOMAN_COBANK_USERNAME=os.getenv('TOMAN_COBANK_USERNAME', ''),
                TOMAN_COBANK_PASSWORD=os.getenv('TOMAN_COBANK_PASSWORD', ''),
                TOMAN_COBANK_FIXED_REFRESH_TOKEN=os.getenv('TOMAN_COBANK_FIXED_REFRESH_TOKEN', ''),
                WIREMOCK_ADMIN_PASSWORD=os.getenv('WIREMOCK_ADMIN_PASSWORD', ''),
                WIREMOCK_ADMIN_USERNAME=os.getenv('WIREMOCK_ADMIN_USERNAME', ''),
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
            if config.WIREMOCK_BASEURL:
                return config
        except Exception:
            pass
        
        # Fallback to config file
        config_file_path = os.path.join(os.path.dirname(__file__), '..', 'wiremock_config.json')
        # Also try the current working directory
        if not os.path.exists(config_file_path):
            config_file_path = 'wiremock_config.json'
        if os.path.exists(config_file_path):
            try:
                with open(config_file_path, 'r') as file:
                    config_data = json.load(file)
                return WireMockEnv(**config_data)
            except (Exception, json.JSONDecodeError) as e:
                print(f"Warning: Could not load config file: {e}")
        
        # Final fallback with empty default values
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


class WiremockManager(Mappings):
    def __init__(self, create_general_stubs: bool = False) -> None:
        self.config = WireMockEnv.get_wiremock_config()
        Config.base_url = f"{self.config.WIREMOCK_BASEURL}/__admin/"
        Config.headers["Authorization"] = (
            f"Basic {base64.b64encode(
            f"{self.config.WIREMOCK_ADMIN_USERNAME}:{self.config.WIREMOCK_ADMIN_PASSWORD}".encode()).decode("utf-8")}"
        )
        self.local_added_mapping_ids_path = "logs/local_added_mapping_ids.txt"
        if create_general_stubs:
            self.delete_all_wiremock_mappings()
            self.generic_permission_denied()
        return

    def add_mapping(self, mapping: Mapping) -> Mapping:
        mapping_id = self.create_mapping(mapping).id
        safe_read_and_append(self.local_added_mapping_ids_path, mapping_id)

    def delete_added_custom_local_mappings(self):
        mappings = read_file(self.local_added_mapping_ids_path).split("\n")
        for m in mappings:
            try:
                self.delete_mapping(m)
            except NotFoundException:
                print("This stub mapping id does not exist, id:", m)
            finally:
                continue
        clear_file(self.local_added_mapping_ids_path)

    def find_mapping_ids_by_url_path_pattern(self, pattern: str):
        mappings = self.retrieve_all_mappings().get_json_data().get("mappings")
        selected_mapppings = []
        for m in mappings:
            request = m.get("request", {})
            if (pattern in request.get("urlPathPattern", "")) or (
                pattern in request.get("urlPattern", "")
            ):
                selected_mapppings.append(m)
        return selected_mapppings

    def delete_all_wiremock_mappings(self):
        Mappings.reset_mappings()

    def generic_permission_denied(self) -> Mapping:
        self.add_mapping(
            Mapping(
                priority=100,
                request=MappingRequest(
                    method=HttpMethods.ANY,
                    urlPattern=".*",
                ),
                response=MappingResponse(
                    status=400,
                    headers={"Content-Type": "application/json"},
                    jsonBody={"message": "Permission denied!!"},
                ),
            )
        )

    def retrieve_all_mappings(self):
        mappings_data = super().retrieve_all_mappings().get_json_data()
        clear_and_write_file(
            "logs/all_mappings.log",
            json.dumps(mappings_data, ensure_ascii=False, indent=2),
        )
        return mappings_data

    def get_all_received_requests(self):
        records_data = Requests.get_all_received_requests().get_json_data()
        clear_and_write_file(
            "logs/all_records.log",
            json.dumps(records_data, ensure_ascii=False, indent=2),
        )
        return records_data
