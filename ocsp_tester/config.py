import json
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class OCSPConfig:
    """Configuration for OCSP Tester application"""
    ocsp_url: str = "http://ocsp.xca.xpki.com/ocsp"
    issuer_path: str = ""
    good_cert: str = ""
    revoked_cert: str = ""
    unknown_ca_cert: str = ""
    # Optional direct serial input for monitor/OCSP checks
    cert_serial: str = ""
    client_cert: str = ""
    client_key: str = ""
    latency_samples: int = 5
    enable_load_test: bool = False
    load_concurrency: int = 5
    load_requests: int = 50
    
    # Monitoring settings
    crl_override_url: str = "http://ocsp.xca.xpki.com"
    check_validity: bool = True
    follow_log: bool = True
    show_info: bool = True
    show_warn: bool = True
    show_cmd: bool = True
    show_stderr: bool = True
    show_status: bool = True
    show_debug: bool = True  # DEBUG logging toggle
    
    # Trust anchor settings
    trust_anchor_path: str = ""
    trust_anchor_type: str = "root"
    require_explicit_policy: bool = False
    inhibit_policy_mapping: bool = False
    
    # Advanced testing options
    test_cryptographic_preferences: bool = True  # Enable cryptographic preference negotiation testing
    test_non_issued_certificates: bool = True    # Enable non-issued certificate testing
    
    # OCSP response validation settings
    max_age_hours: int = 24  # Maximum age in hours for OCSP response thisUpdate field


class ConfigManager:
    """Manages saving and loading of configuration"""
    
    def __init__(self, config_file: str = "ocsp_config.json"):
        # Prefer a user-writable location by default (Windows LOCALAPPDATA if available; else home dir)
        local_appdata = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA")
        if local_appdata:
            default_dir = os.path.join(local_appdata, "OCSPTesting")
        else:
            default_dir = os.path.join(os.path.expanduser("~"), ".ocsp_testing")
        os.makedirs(default_dir, exist_ok=True)

        user_config_path = os.path.join(default_dir, "ocsp_config.json")

        # If a custom path was provided, honor it; otherwise use the user config path
        self.config_file = user_config_path if config_file == "ocsp_config.json" else config_file
        # Legacy path (project root) for backward-compat loading
        self.legacy_config_file = "ocsp_config.json"
        self.config = OCSPConfig()
    
    def load_config(self) -> OCSPConfig:
        """Load configuration from file"""
        candidates = [self.config_file]
        # Also try legacy project-root file if different
        if self.legacy_config_file not in candidates:
            candidates.append(self.legacy_config_file)

        for path in candidates:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        # Update config with loaded data
                        for key, value in data.items():
                            if hasattr(self.config, key):
                                setattr(self.config, key, value)
                    # If we loaded from legacy location, attempt to migrate by saving to new location
                    if path != self.config_file:
                        try:
                            self.save_config(self.config)
                        except Exception:
                            # Non-fatal if migration fails
                            pass
                    break
                except Exception as e:
                    print(f"Error loading config from {path}: {e}")
                    # Try next candidate
                    continue
        return self.config
    
    def save_config(self, config: OCSPConfig) -> bool:
        """Save configuration to file (atomic, with fallback-friendly path)"""
        try:
            # Ensure directory exists
            config_dir = os.path.dirname(self.config_file) or "."
            os.makedirs(config_dir, exist_ok=True)

            tmp_path = self.config_file + ".tmp"
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(asdict(config), f, indent=2)
            # Atomic replace where supported (Windows: os.replace also overwrites)
            os.replace(tmp_path, self.config_file)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def update_from_dict(self, data: Dict[str, Any]) -> None:
        """Update config from dictionary"""
        for key, value in data.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
