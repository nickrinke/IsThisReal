"""
MSAL authentication for Microsoft Graph API.

Supports Commercial, GCC, and GCC-High tenants via config.
Uses client credential flow (application permissions) so it can
run unattended against a shared mailbox.
"""
import logging
import msal
from .config import get_settings

logger = logging.getLogger(__name__)

_token_cache: msal.TokenCache = msal.TokenCache()
_app: msal.ConfidentialClientApplication | None = None


def _get_msal_app() -> msal.ConfidentialClientApplication:
    global _app
    if _app is None:
        settings = get_settings()
        _app = msal.ConfidentialClientApplication(
            client_id=settings.azure_client_id,
            client_credential=settings.azure_client_secret,
            authority=settings.azure_authority,
            token_cache=_token_cache,
        )
    return _app


def get_access_token() -> str:
    """
    Acquire a Graph API access token using client credentials.
    Uses cached token if available and not expired.
    """
    settings = get_settings()
    app = _get_msal_app()

    # Try silent (cached) first
    result = app.acquire_token_silent(
        scopes=settings.graph_scope,
        account=None,
    )

    if not result:
        logger.debug("No cached token, acquiring new token via client credentials")
        result = app.acquire_token_for_client(scopes=settings.graph_scope)

    if "access_token" in result:
        return result["access_token"]

    error = result.get("error_description", result.get("error", "Unknown error"))
    logger.error(f"Failed to acquire token: {error}")
    raise RuntimeError(f"MSAL token acquisition failed: {error}")
