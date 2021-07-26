# -*- coding: utf-8 -*-

from flask import Blueprint
from flask_cors import CORS

api_v1 = Blueprint('api_v1', __name__)

CORS(api_v1) # 资源跨域保护

from todoism.apis.v1 import resources
