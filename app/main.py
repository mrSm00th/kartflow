import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.redis_client import ping_redis
from app.db.database import engine, get_db
from app.db.models_registry import load_models
from app.modules.addresses import router as addresses
from app.modules.admins import router as admins
from app.modules.carts import router as carts
from app.modules.locations import router as locations
from app.modules.menus import router as menus
from app.modules.notifications import router as notifications
from app.modules.orders import customer_orders_router as customer_orders
from app.modules.orders import restaurant_orders_router as restaurant_orders
from app.modules.partner_applications import router as partner_applications
from app.modules.payments.router import router as payments_router
from app.modules.realtime import router as realtime
from app.modules.restaurants import router as restaurants
from app.modules.reviews.router import my_reviews_router, public_router
from app.modules.reviews.router import router as review_router
from app.modules.rider_applications import router as admmin_rider_application
from app.modules.rider_applications import router as rider_applications
from app.modules.riders import payout_router
from app.modules.riders import router as riders
from app.modules.users import router as users

logger = logging.getLogger(__name__)


# generatings tables using alembic
@asynccontextmanager
async def lifespan(app: FastAPI):
    redis_ok = await ping_redis()
    if redis_ok:
        logger.info("Redis connected — activated caching")
    else:
        logger.warning("Redis unavailable — running without cache")
    yield


app = FastAPI(lifespan=lifespan)

load_models()

BASE_DIR = Path(__file__).resolve().parent.parent

templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

app.include_router(users.router, prefix="/api")
app.include_router(partner_applications.router, prefix="/api")
app.include_router(admins.router, prefix="/api")
app.include_router(restaurants.router, prefix="/api")
app.include_router(menus.router, prefix="/api")
app.include_router(carts.router, prefix="/api")
app.include_router(addresses.router, prefix="/api")
app.include_router(payments_router, prefix="/api")
app.include_router(
    restaurant_orders.restaurant_orders_router,
    prefix="/api",
)  # handles the incomming orders and stuff
app.include_router(
    restaurant_orders.order_actions_router,
    prefix="/api",
)  # handles acting upon that orders like acc / rej
app.include_router(realtime.router, prefix="/api")
app.include_router(notifications.router, prefix="/api")
app.include_router(locations.router, prefix="/api")
app.include_router(customer_orders.router, prefix="/api")
app.include_router(rider_applications.router, prefix="/api")
app.include_router(admmin_rider_application.admin_router, prefix="/api")
app.include_router(riders.router, prefix="/api")

app.include_router(review_router, prefix="/api")
app.include_router(my_reviews_router, prefix="/api")
app.include_router(public_router, prefix="/api")

app.include_router(payout_router.router, prefix="/api")


@app.get(
    "/",
    name="home",
)
async def home(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):

    return templates.TemplateResponse(
        request,
        "home.html",
        {
            "title": "Home",
        },
    )
