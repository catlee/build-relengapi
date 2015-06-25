from relengapi.lib import db

import logging

from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy.orm import relation

log = logging.getLogger(__name__)

class DbTree(db.declarative_base('treestatus')):
    __tablename__ = 'trees'
    tree = Column(String(32), primary_key=True)
    status = Column(String(64), default="open", nullable=False)
    reason = Column(String(256), default="", nullable=False)
    message_of_the_day = Column(String(800), default="", nullable=False)

    def to_dict(self):
        return dict(
            tree=self.tree,
            status=self.status,
            reason=self.reason,
            message_of_the_day=self.message_of_the_day,
            )


class DbLog(db.declarative_base('treestatus')):
    __tablename__ = 'log'
    id = Column(Integer, primary_key=True)
    tree = Column(String(32), nullable=False, index=True)
    when = Column(DateTime, nullable=False, index=True)
    who = Column(String(100), nullable=False)
    action = Column(String(16), nullable=False)
    reason = Column(String(256), nullable=False)
    tags = Column(String(256), nullable=False)

    def to_dict(self):
        return dict(
            tree=self.tree,
            when=self.when.strftime("%Y-%m-%dT%H:%M:%S%Z"),
            who=self.who,
            action=self.action,
            reason=self.reason,
            tags=self.tags,
            )


class DbToken(db.declarative_base('treestatus')):
    __tablename__ = 'tokens'
    who = Column(String(100), nullable=False, primary_key=True)
    token = Column(String(100), nullable=False)

    @classmethod
    def delete(cls, who):
        q = cls.__table__.delete(cls.who == who)
        q.execute()

    @classmethod
    def get(cls, who):
        q = cls.__table__.select(cls.who == who)
        result = q.execute().fetchone()
        return result


class DbStatusStack(db.declarative_base('treestatus')):
    __tablename__ = 'status_stacks'
    id = Column(Integer, primary_key=True)
    who = Column(String(100), nullable=False)
    reason = Column(String(256), nullable=False)
    when = Column(DateTime, nullable=False, index=True)
    status = Column(String(64), nullable=False)


class DbStatusStackTree(db.declarative_base('treestatus')):
    __tablename__ = 'status_stack_trees'
    id = Column(Integer, primary_key=True)
    stack_id = Column(Integer, ForeignKey(DbStatusStack.id), index=True)
    tree = Column(String(32), nullable=False, index=True)
    last_state = Column(String(1024), nullable=False)

    stack = relation(DbStatusStack, backref='trees')


class DbUser(db.declarative_base('treestatus')):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), index=True)
    is_admin = Column(Boolean, nullable=False, default=False)
    is_sheriff = Column(Boolean, nullable=False, default=False)

    @classmethod
    def get(cls, name):
        q = cls.__table__.select(cls.name == name)
        result = q.execute().fetchone()
        return result
