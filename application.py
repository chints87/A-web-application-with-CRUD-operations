from flask import Flask, render_template
app = Flask(__name__)

@app.route('/login') 
def login(): 
    return ('This is the login page')

@app.route('/')
@app.route('/catalog')
def showCatalog():
    return ('This shows all the categories and latest added items')

@app.route('/catalog/additem')
def newItem():
    return ('This is a form to enter new item')

@app.route('/catalog/category/items')
def showItems(): 
    return ('Displays all available items in a specific category')

@app.route('/catalog/category/item_name')
def showDetails(): 
    return('Displays the description of that item in the specfic category')

@app.route('/catalog/category/item_name/edit')
def editItem(): 
    return ('Edit item')

@app.route('/catalog/category/item_name/delete')
def deleteItem(): 
    return ('Delete item')

if __name__ == '__main__': 
    app.debug = True
    app.run(host = '0.0.0.0', port = 8000)

