import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)


class Role(Base):
    __tablename__ = 'role'

    role_id = Column(Integer, primary_key=True)
    rolename = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):

        return {
               'role_id': self.role_id,
               'rolename': self.rolename,
               'user_id': self.user_id,
               }


class Employees(Base):
    __tablename__ = 'employees'

    name = Column(String(80), nullable=False)
    emp_id = Column(Integer, primary_key=True)

    role_id = Column(Integer, ForeignKey('role.role_id'))
    role = relationship(Role)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):

        return {
               'name': self.name,
               'emp_id': self.role_id,
               }

engine = create_engine('sqlite:///employee.db')
Base.metadata.create_all(engine)
