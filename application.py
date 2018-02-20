from flask import Flask, render_template, url_for, redirect, flash, request
from sqlalchemy import create_engine, and_ , func
from sqlalchemy.orm import sessionmaker
from catalog_database_setup import Base, Category, Items
app = Flask(__name__)

from flask import session as login_session # like a dictionary that stores user longevity with server
import random, string

from oauth2client.client import flow_from_clientsecrets #store json formatted style clientid, clientsecret and other oauth2 parameters
from oauth2client.client import FlowExchangeError # catch error when trying to exchange an authorization code for an access token 
import httplib2 # http client lib in python 
import json # provides an API converting in memory python objects to a serialized rep. known as Json
from flask import make_response #converts return value from a function into a real response object that we can send to our client 
import requests # apache 2.0 licensed HTTP library written in python


engine = create_engine('sqlite:///catalogdb.db')
Base.metadata.bind = engine 

DBsession = sessionmaker(bind = engine)
session = DBsession()
# category = [{'name':'cricket', 'id' : '1'} , {'name':'soccer', 'id':'1'} , \
#  {'name':'tennis', 'id':'3'}] 
# latest_items = [{'item':'Gloves','category' : 'Cricket'}, \
# {'item': 'Shin guard', 'category': 'Soccer'} ,{'item':'Rackets', 'category' : 'Tennis'}] 
# items = [{'cricket': [{'item':'helmet','id' : '1', 'description' : 'protects the head' }, {'item':'gloves', 'id': '2'}, \
# {'item':'bat', 'id' :'3'}, {'item':'guard', 'id' : '4'}]}]

@app.route('/login') 
def login(): 
    # return ('This is the login page')
    return render_template('login.html')

@app.route('/')
@app.route('/catalog', methods = ['GET'])
def showCatalog():  
    category = session.query(Category)
    items = session.query(Items).order_by("Items.created_date desc").limit(5)
    return render_template('catalog.html', category = category, items = items)

@app.route('/catalog/additem', methods = ['GET','POST'])
def newItem(): 
    if request.method == 'POST':
        is_category = session.query(Category).filter_by(name = request.form['category']) \
        .scalar()
        if is_category is None:
           new_category = Category(name = request.form['category']) 
           session.add(new_category)
           session.commit()
        category = session.query(Category).filter_by(name = request.form['category']).one()
        item = Items(name = request.form['name'], description = request.form['description'], \
         category_id = category.id)        
        session.add(item)
        session.commit()
        return redirect(url_for('showCatalog'))
    else: 
        return render_template('newItem.html')

@app.route('/catalog/<string:category_name>/items', methods = ['GET', 'POST'])
def showItems(category_name):
    category = session.query(Category)
    specific_category = session.query(Category).filter_by(name = category_name).one()
    category_items = session.query(Items).filter_by(category_id= specific_category.id).all()
    category_items_count = session.query(Items).filter_by(category_id= specific_category.id).count()
    return render_template('categoryitems.html', category = category, category_items = category_items, \
    category_name = specific_category.name, category_items_count = category_items_count)

@app.route('/catalog/<string:category_name>/<string:item_name>', methods = ['GET', 'POST'])
def showDetails(category_name,item_name): 
    category = session.query(Category).filter_by(name = category_name).one()
    item = session.query(Items).filter_by(category_id = category.id).all()     
    specific_item = session.query(Items).filter_by(name = item_name). one()    
    return render_template('itemdetail.html', item_name = item_name, \
     item_description = specific_item.description, category_name = category_name)

@app.route('/catalog/<string:category_name>/<string:item_name>/edit', methods = ['GET', 'POST'])
def editItem(category_name,item_name):  
    edit_category = session.query(Category).filter_by(name = category_name).one() 
    editeditem = session.query(Items).filter_by(id = edit_category.id, name = item_name).one()   
    
    if request.method == "POST": 
        for key in request.form.keys():            
            if key == 'name' and request.form[key]:                
                editeditem.name = request.form[key]
            if key == 'description' and request.form[key]:             
                editeditem.description = request.form[key]
            if key == 'category' and request.form[key]:                
                editeditem.category = request.form[key]        
        session.add(editeditem)  
        session.commit()            
        return redirect(url_for('showCatalog'))
    else : 
        return render_template('edititem.html', editeditem = editeditem, category_name = category_name \
        ,item_name = item_name)


@app.route('/catalog/<string:category_name>/<string:item_name>/delete', methods = ['GET', 'POST'])
def deleteItem(category_name,item_name): 
    delete_category = session.query(Category).filter_by(name = category_name).one()    
    deleteditem = session.query(Items).filter_by(category_id = delete_category.id, name = item_name).one()
    if request.method == "POST":
        session.delete(deleteditem)
        session.commit()
        return redirect(url_for('showCatalog'))
    else: 
       return render_template('deleteitem.html', category_name = category_name, item_name = item_name)

if __name__ == '__main__': 
    app.debug = True
    app.run(host = '0.0.0.0', port = 8000)

