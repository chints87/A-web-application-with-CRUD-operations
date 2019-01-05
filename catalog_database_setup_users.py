import os
import sys 
import datetime

from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

#The database stores details of the user that log into the system via 
#Google or Facebook 

class User(Base):

#The table created here is used to store user details
    __tablename__ = 'user'

    name = Column(String(80), nullable = False)
    email = Column(String(80), nullable = False)
    picture = Column(String(200))
    id = Column(Integer, primary_key = True)   
     

class Category(Base):

#The table created here stores category details
    __tablename__ = 'category'

    name = Column(String(80), nullable = False)
    id = Column(Integer,primary_key = True) 

#The object returned creates json endpoints for categories    
    @property
    def serializable(self):
        return {
        'name' : self.name,
        'id' : self.id,  
        }      
        

class Items(Base):   

#The table here is used to store items details along with its repsective category details
    __tablename__ = 'items'

    name = Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    description = Column(String(500), nullable = False)
    created_date = Column(DateTime, default=datetime.datetime.now)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

#The object returned creates json endpoints for items      
    @property
    def serializable(self):
        return {
        'cat name': self.category.name,
        'category_id': self.category_id,
        'item name' : self.name,
        'id' : self.id,
        'description' : self.description,                         
        }


#Creates the database named 'catalogdbusers'
engine = create_engine('sqlite:///catalogdbusers.db')
Base.metadata.create_all(engine)

