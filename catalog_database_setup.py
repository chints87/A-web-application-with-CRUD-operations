import os
import sys 
import datetime

from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

#CLASS : TO REPRESENT DATA IN PYTHON

# To let SQLAlchemy to know the variable that 
# we will use to refer to our table. 
class Category(Base):

    __tablename__ = 'category'

    name = Column(String(80), nullable = False)
    id = Column(Integer,primary_key = True)    

class Items(Base):   

    __tablename__ = 'items'

    name = Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    description = Column(String(500), nullable = False)
    created_date = Column(DateTime, default=datetime.datetime.now)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)

engine = create_engine('sqlite:///catalogdb.db')

Base.metadata.create_all(engine)

