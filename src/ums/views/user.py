from .base import BaseView
from ums.models import schemas


class UserResponse(BaseView):
    content: schemas.User
