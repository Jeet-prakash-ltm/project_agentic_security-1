import os


class Settings:

    FW_HOST = os.getenv("NETSEC_FW_HOST")
    FW_PORT = int(os.getenv("NETSEC_FW_PORT", "443"))

    FW_USERNAME = os.getenv("NETSEC_FW_USERNAME")
    FW_PASSWORD = os.getenv("NETSEC_FW_PASSWORD")

    FW_API_KEY = os.getenv("NETSEC_FW_API_KEY")

    VERIFY_TLS = (
        os.getenv("NETSEC_FW_VERIFY_TLS", "true").lower()
        == "true"
    )

    TIMEOUT = int(os.getenv("NETSEC_FW_TIMEOUT", "30"))

    DRY_RUN = (
        os.getenv("NETSEC_FW_DRY_RUN", "1")
        == "1"
    )

    @classmethod
    def validate(cls):

        if not cls.FW_HOST:
            raise ValueError(
                "NETSEC_FW_HOST is not configured"
            )