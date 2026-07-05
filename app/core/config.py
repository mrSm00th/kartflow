from decimal import Decimal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str

    secret_key: SecretStr
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 30

    razorpay_key_id: str
    razorpay_key_secret: str
    razorpay_webhook_secret: str

    application_per_page: int = 10

    storage_backend: str = "local"

    # s3 / supabase storage
    s3_public_bucket_name: str = "kartflow-public"
    s3_private_bucket_name: str = "kartflow-private"
    s3_region: str = "ap-south-1"
    s3_endpoint_url: str | None = None
    s3_access_key_id: SecretStr | None = None
    s3_secret_access_key: SecretStr | None = None

    max_upload_size_bytes: int = Field(
        default=5 * 1024 * 1024,
        ge=1024,
        le=10 * 1024 * 1024,
    )

    max_images_per_restaurant: int = 20
    restaurants_per_page: int = 10
    notifications_per_page: int = 10
    max_dining_menu_images_per_restaurant: int = 50
    max_restaurant_images_per_request: int = 10
    max_restaurant_dining_menu_images_per_request: int = 10
    max_restaurant_food_images_per_request: int = 5

    approved_cuisine_names_per_page: int = 10
    menuItems_per_catagory_per_page: int = 10
    menu_categories_per_page: int = 10
    menu_items_per_page: int = 10

    tax_rate: Decimal = Decimal("0.18")

    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"
    order_response_timeout_minutes: int = 5

    pii_encryption_key: str

    rider_assignment_timeout_minutes: int = 10

    base_delivery_price: float = 20.0
    delivery_free_radius_km: float = 2.0
    delivery_near_rate_per_km: float = 8.0
    delivery_far_threshold_km: float = 5.0
    delivery_far_rate_per_km: float = 12.0
    delivery_max_fee: float = 150.0

    redis_url: str = "redis://localhost:6379/1"

    CACHE_TTL_RESTAURANT_DETAIL: int = 60
    CACHE_TTL_REVIEWS: int = 300
    CACHE_TTL_CUISINE_LIST: int = 3600
    CACHE_TTL_DISH_SEARCH: int = 60
    CACHE_TTL_DISCOVERY_FEED: int = 30

    # email

    smtp_host: str = "smtp-relay.brevo.com"
    smtp_port: int = 587
    smtp_user: str
    smtp_password: str
    mail_from_name: str
    mail_from: str
    mail_use_tls: bool = True

    frontend_url: str = "http://localhost:3000"

    # otp
    otp_expire_minutes: int = 10


settings = Settings()
