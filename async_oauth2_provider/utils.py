from async_oauth2_provider.config import oauth2_settings


def is_secure_transport(uri):
    """Check if the uri is over ssl."""
    if oauth2_settings.INSECURE_TRANSPORT:
        return True
    return uri.lower().startswith("https://")
