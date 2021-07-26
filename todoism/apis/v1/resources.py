# -*- coding: utf-8 -*-
# 所有表示资源的视图
from flask import jsonify, request, current_app, url_for, g
from flask.views import MethodView

from todoism.apis.v1 import api_v1
from todoism.apis.v1.auth import auth_required, generate_token
from todoism.apis.v1.errors import api_abort, ValidationError
from todoism.apis.v1.schemas import user_schema, item_schema, items_schema, point_schema
from todoism.extensions import db
from todoism.models import User, Item, Point


def get_item_body():
    # data = request.get_json()
    # body = data.get('body')
    body = request.form.get('body', None)
    if body is None or str(body).strip() == '':
        raise ValidationError('The item body was empty or invalid.')
    return body

# 获取传递的段名称
def get_point_data(name):
    # body = request.form.get(name, None)
    data = request.get_json()
    body = data.get(name)
    if body is None or str(body).strip() == '':
        raise ValidationError('The item body was empty or invalid.')
    return body

class IndexAPI(MethodView):

    def get(self):
        return jsonify({
            "api_version": "1.0",
            "api_base_url": "http://example.com/api/v1",
            "current_user_url": "http://example.com/api/v1/user",
            "authentication_url": "http://example.com/api/v1/token",
            "item_url": "http://example.com/api/v1/items/{item_id }",
            "current_user_items_url": "http://example.com/api/v1/user/items{?page,per_page}",
            "current_user_active_items_url": "http://example.com/api/v1/user/items/active{?page,per_page}",
            "current_user_completed_items_url": "http://example.com/api/v1/user/items/completed{?page,per_page}",
            "add_point_url": "http://example.com/api/v1/point",
            "point_detail_url": "http://example.com/api/v1/point{point_id}",
        })


class AuthTokenAPI(MethodView):

    # http://127.0.0.1:5000/api/v1/oauth/token
    # form方式传参
    def post(self):
        grant_type = request.form.get('grant_type')
        username = request.form.get('username')
        password = request.form.get('password')

        if grant_type is None or grant_type.lower() != 'password':
            return api_abort(code=400, message='The grant type must be password.')

        user = User.query.filter_by(username=username).first()
        if user is None or not user.validate_password(password):
            return api_abort(code=400, message='Either the username or password was invalid.')

        token, expiration = generate_token(user)

        response = jsonify({
            'access_token': token,
            'token_type': 'Bearer',
            'expires_in': expiration
        })
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'
        return response


class ItemAPI(MethodView):
    decorators = [auth_required]

    def get(self, item_id):
        """Get item."""
        item = Item.query.get_or_404(item_id)
        if g.current_user != item.author:
            return api_abort(403)
        return jsonify(item_schema(item))

    def put(self, item_id):
        """Edit item."""
        item = Item.query.get_or_404(item_id)
        if g.current_user != item.author:
            return api_abort(403)
        item.body = get_item_body()
        db.session.commit()
        return '', 204

    def patch(self, item_id):
        """Toggle item."""
        item = Item.query.get_or_404(item_id)
        if g.current_user != item.author:
            return api_abort(403)
        item.done = not item.done
        db.session.commit()
        return '', 204

    def delete(self, item_id):
        """Delete item."""
        item = Item.query.get_or_404(item_id)
        if g.current_user != item.author:
            return api_abort(403)
        db.session.delete(item)
        db.session.commit()
        return '', 204


class UserAPI(MethodView):
    decorators = [auth_required]

    def get(self):
        return jsonify(user_schema(g.current_user))

# 调试中。。。sa_instance_state
class ItemsAPI(MethodView):
    decorators = [auth_required]

    def get(self):
        """Get current user's all items."""
        page = request.args.get('page', 1, type=int)
        per_page = current_app.config['TODOISM_ITEM_PER_PAGE']
        pagination = Item.query.with_parent(g.current_user).paginate(page, per_page)
        items = pagination.items
        current = url_for('.items', page=page, _external=True)
        prev = None
        if pagination.has_prev:
            prev = url_for('.items', page=page - 1, _external=True)
        next = None
        if pagination.has_next:
            next = url_for('.items', page=page + 1, _external=True)
        return jsonify(items_schema(items, current, prev, next, pagination))

    def post(self):
        """Create new item."""
        item = Item(body=get_item_body()) # author=g.current_user

        db.session.add(item)
        db.session.commit()

        response = jsonify(item_schema(item))
        response.status_code = 201
        response.headers['Location'] = url_for('.item', item_id=item.id, _external=True)
        return response


class ActiveItemsAPI(MethodView):
    decorators = [auth_required]

    def get(self):
        """Get current user's active items."""
        page = request.args.get('page', 1, type=int)
        pagination = Item.query.with_parent(g.current_user).filter_by(done=False).paginate(
            page, per_page=current_app.config['TODOISM_ITEM_PER_PAGE'])
        items = pagination.items
        current = url_for('.items', page=page, _external=True)
        prev = None
        if pagination.has_prev:
            prev = url_for('.active_items', page=page - 1, _external=True)
        next = None
        if pagination.has_next:
            next = url_for('.active_items', page=page + 1, _external=True)
        return jsonify(items_schema(items, current, prev, next, pagination))


class CompletedItemsAPI(MethodView):
    decorators = [auth_required]

    def get(self):
        """Get current user's completed items."""
        page = request.args.get('page', 1, type=int)
        pagination = Item.query.with_parent(g.current_user).filter_by(done=True).paginate(
            page, per_page=current_app.config['TODOISM_ITEM_PER_PAGE'])
        items = pagination.items
        current = url_for('.items', page=page, _external=True)
        prev = None
        if pagination.has_prev:
            prev = url_for('.completed_items', page=page - 1, _external=True)
        next = None
        if pagination.has_next:
            next = url_for('.completed_items', page=page + 1, _external=True)
        return jsonify(items_schema(items, current, prev, next, pagination))

    def delete(self):
        """Clear current user's completed items."""
        Item.query.with_parent(g.current_user).filter_by(done=True).delete()
        db.session.commit()  # TODO: is it better use for loop?
        return '', 204


'''
获取某一个具体的监控点的数据， 传两个参数  段名 segment 和  监控点名 point
'''
class PointsAPI(MethodView):
    # decorators = [auth_required]

    # 增
    def post(self):
        """Create new point."""
        point = Point(segment=get_point_data(name='segment'), point=get_point_data(name='point'), temperature=get_point_data(name='temperature'), humidity=get_point_data(name='humidity'),windpressure=get_point_data(name='windpressure'),status=get_point_data(name='status'))
        # print(point)
        # return '32145'
        db.session.add(point)
        db.session.commit()
        response = jsonify(point_schema(point))
        response.status_code = 201
        response.headers['Location'] = url_for('.point', item_id=point.id, _external=True)
        return response


class PointAPI(MethodView):
    # decorators = [auth_required]

    # 查
    def get(self, point_id):
        """Get point."""
        point = Point.query.get_or_404(point_id)
        # if g.current_user != item.author:
        #     return api_abort(403)
        return jsonify(point_schema(point))

# 注册路由， 必须
api_v1.add_url_rule('/', view_func=IndexAPI.as_view('index'), methods=['GET'])
api_v1.add_url_rule('/oauth/token', view_func=AuthTokenAPI.as_view('token'), methods=['POST'])
api_v1.add_url_rule('/user', view_func=UserAPI.as_view('user'), methods=['GET'])
api_v1.add_url_rule('/user/items', view_func=ItemsAPI.as_view('items'), methods=['GET', 'POST'])
api_v1.add_url_rule('/user/items/<int:item_id>', view_func=ItemAPI.as_view('item'),
                    methods=['GET', 'PUT', 'PATCH', 'DELETE'])
api_v1.add_url_rule('/user/items/active', view_func=ActiveItemsAPI.as_view('active_items'), methods=['GET'])
api_v1.add_url_rule('/user/items/completed', view_func=CompletedItemsAPI.as_view('completed_items'),
                    methods=['GET', 'DELETE'])
# 关于监测点的路由
api_v1.add_url_rule('/point', view_func=PointsAPI.as_view('points'), methods=['POST']) # 增加一个新的监测点
api_v1.add_url_rule('/point/<int:point_id>', view_func=PointAPI.as_view('point'),
                    methods=['GET', 'PUT', 'PATCH', 'DELETE']) # 对一个具体的监测点的操作