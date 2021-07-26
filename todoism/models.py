# -*- coding: utf-8 -*-

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from todoism.extensions import db


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    locale = db.Column(db.String(20))
    # items = db.relationship('Item', back_populates='author', cascade='all')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def validate_password(self, password):
        return check_password_hash(self.password_hash, password)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    done = db.Column(db.Boolean, default=False)
    # author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # author = db.relationship('User', back_populates='items')


# 监测点数据监测
class Point(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    segment = db.Column(db.String(64), default='', nullable=False, comment='大段名，X1段')
    point = db.Column(db.String(64), default='', nullable=False, comment='监测点名，5号监测点')
    temperature = db.Column(db.Integer, default=0, comment='温度')
    humidity = db.Column(db.Integer, default=0, comment='湿度')
    windpressure = db.Column(db.Integer, default=0, comment='风压')
    status = db.Column(db.Integer, default=3, nullable=False, comment='状态，1停止，2警告，3正常，其他值都不属于正常值')

