from flask import Flask, render_template
app = Flask(__name__)

@app.route('/login') 
def login(): 
    # return ('This is the login page')
    return render_template('login.html')

@app.route('/')
@app.route('/catalog')
def showCatalog():
    return render_template('catalog.html')

@app.route('/catalog/additem')
def newItem():
    return render_template('newItem.html')

@app.route('/catalog/category/items')
def showItems(): 
    return render_template('categoryitems.html')

@app.route('/catalog/category/item_name')
def showDetails(): 
    return render_template('itemdetail.html')

@app.route('/catalog/category/item_name/edit')
def editItem(): 
    return render_template('edititem.html')

@app.route('/catalog/category/item_name/delete')
def deleteItem(): 
    return render_template('deleteitem.html')

if __name__ == '__main__': 
    app.debug = True
    app.run(host = '0.0.0.0', port = 8000)

