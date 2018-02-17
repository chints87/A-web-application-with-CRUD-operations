from flask import Flask, render_template, url_for
app = Flask(__name__)

category = [{'name':'cricket', 'id' : '1'} , {'name':'soccer', 'id':'1'} , \
 {'name':'tennis', 'id':'3'}] 
latest_items = [{'item':'Gloves','category' : 'Cricket'}, \
{'item': 'Shin guard', 'category': 'Soccer'} ,{'item':'Rackets', 'category' : 'Tennis'}] 
items = [{'cricket': [{'item':'helmet','id' : '1', 'description' : 'protects the head' }, {'item':'gloves', 'id': '2'}, \
{'item':'bat', 'id' :'3'}, {'item':'guard', 'id' : '4'}]}]

@app.route('/login') 
def login(): 
    # return ('This is the login page')
    return render_template('login.html')

@app.route('/')
@app.route('/catalog')
def showCatalog(category = category, latest_items = latest_items):    
    return render_template('catalog.html', category = category, latest_items = latest_items)

@app.route('/catalog/additem')
def newItem():
    return render_template('newItem.html', category = category, latest_items = latest_items)

@app.route('/catalog/cricket/items')
def showItems(category = category, items = items):       
    return render_template('categoryitems.html', category = category, items = items)

@app.route('/catalog/cricket/helmet')
def showDetails():        
    return render_template('itemdetail.html', items = items)

@app.route('/catalog/cricket/helmet/edit')
def editItem(): 
    return render_template('edititem.html', items = items, category = category)

@app.route('/catalog/cricket/helmet/delete')
def deleteItem(): 
    return render_template('deleteitem.html', items = items)

if __name__ == '__main__': 
    app.debug = True
    app.run(host = '0.0.0.0', port = 8000)

