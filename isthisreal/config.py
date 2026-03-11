from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Entra ID / MSAL
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""

    # Mailbox to monitor (shared mailbox or user mailbox)
    isthisreal_mailbox: str = "isthisreal@yourdomain.com"

    # Graph API endpoints — GCC uses different base URLs
    # Commercial: https://graph.microsoft.com
    # GCC: https://graph.microsoft.com
    # GCC-High: https://graph.microsoft.us
    graph_base_url: str = "https://graph.microsoft.com"
    graph_api_version: str = "v1.0"

    # MSAL authority — GCC uses different authority
    # Commercial / GCC: https://login.microsoftonline.com
    # GCC-High: https://login.microsoftonline.us
    azure_authority_host: str = "https://login.microsoftonline.com"

    # Anthropic
    anthropic_api_key: str = ""

    # Polling
    poll_interval_seconds: int = 30
    max_messages_per_poll: int = 10

    # API cost control — minimum finding score to call Claude API
    # RED finding = 10 pts, YELLOW = 5 pts. Below threshold = free canned verdict.
    escalation_threshold: int = 5

    # Optional
    whois_timeout: int = 5
    log_level: str = "INFO"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @property
    def azure_authority(self) -> str:
        return f"{self.azure_authority_host}/{self.azure_tenant_id}"

    @property
    def graph_scope(self) -> list[str]:
        """MSAL client credential scope for Graph API."""
        base = self.graph_base_url.rstrip("/")
        return [f"{base}/.default"]

    @property
    def graph_url(self) -> str:
        return f"{self.graph_base_url}/{self.graph_api_version}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
