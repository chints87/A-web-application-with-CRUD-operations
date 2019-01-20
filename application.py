import random
import string
import httplib2  # http client lib in python
import json  # provides an API converting in memory python objects 
#to a serialized rep. known as Json
import requests  # apache 2.0 licensed HTTP library written in python
from flask import Flask, render_template, url_for, redirect, flash, request, jsonify
# like a dictionary that stores user longevity with server
from flask import session as login_session
# store json formatted style clientid, clientsecret and other oauth2 parameters
from oauth2client.client import flow_from_clientsecrets
# catch error when trying to exchange an authorization code for an access token
from oauth2client.client import FlowExchangeError
# converts return value from a function into a real response object that
# we can send to our client
from flask import make_response

from sqlalchemy import create_engine, and_, func
from sqlalchemy.orm import sessionmaker
from catalog_database_setup_users import User, Base, Category, Items
app = Flask(__name__)

# Store web app credentials
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog"

engine = create_engine('sqlite:///catalogdbusers.db')
Base.metadata.bind = engine

DBsession = sessionmaker(bind=engine)
session = DBsession()

# Login page


@app.route('/login')
def showLogin():
    # unique session token generation
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # html page is generated with a token
    return render_template('login.html', STATE=state)

# Connecting web app using gmail


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Using the state generated in the server is checked against the state
    # sent from the login page
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # collect one-time code
    code = request.data
    try:
        # Upgrade from authorization code into a credentials object
        # Creates an oauthflow object and adds client secret key information to
        # it
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        # Passing one time code as input exchanges an authorization code for a
        # credentials object that contains the access code for the web server
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check that the access token is valid
    # Storing credentials access token in the access token variable
    access_token = credentials.access_token

    # Google API server can verify that if this is a valid token for use
    url = ("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}".format(access_token))
    # json GET request containing url and access token
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        # If not true then we have working access token
        response = make_response(json.dumps(results.get('error')), 500)
        response.headers['Content-Type'] = 'application.json'
        return response
    # verify if the access token is used for the intended user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match apps"), 401)
        print "Token's client ID does not match apps"
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check to see if user is already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'

    # Store the access token in the session for later use
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info from the google plus api. A message is sent to the
    # Google API server with my access token,
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}

    # Send off message to google API with access token
    # requesting user info allowed
    # by the token scope and stored in an object called data
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    # Storing info in the login session
    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    # Create a response that knows the username and picture
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
# This is done by telling the server to reject its access token

@app.route("/gdisconnect")
def gdisconnect():
    print("in gdisconnect")
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result

    # If succesful then user info is deleted, else error message shown which
    # is a bad request.

    if result['status'] == '200':

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps(
                'Failed to revoke token for given user.',
                400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    print ("in fbconnect")
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data

    # Exchange client token for long-lived server-side token with
    # oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token={short-lived-token}'

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_secret']  # to verify server identity
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    # Extract the access token from response
    token = 'access_token=' + data['access_token']

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.9/me"

    # strip expire tag from access token since do not need it to be make API
    # calls
    token = result.split(',')[0].split(':')[1].replace('"', '')

    # If token works, then one should be able to make API calls with the new
    # token
    url = 'https://graph.facebook.com/v2.9/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # Get user picture. FB uses a seperate API call to obtain profile picture
    url = 'https://graph.facebook.com/v2.9/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session.get('access_token')
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "You have been logged out"

# JSON endpoints


@app.route('/catalog/JSON')
def showcatalogJSON():

    Catalog = {}
    Catalog['Category'] = []

    category = session.query(Category).all()
    for i in category:
        print (i.serializable)
        Catalog['Category'].append([i.serializable])
        items = session.query(Items).filter_by(category_id=i.id).all()
        for j in items:
            Catalog['Category'].append([j.serializable])
    return jsonify(Catalog)


@app.route('/catalog/<string:category_name>/JSON')
def categoryitemJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Items).filter_by(category_id=category.id).all()
    return jsonify(CategoryItem=[i.serializable for i in items])


@app.route('/catalog/<string:category_name>/<string:item_name>/JSON')
def singleitemJSON(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Items).filter_by(category_id=category.id).all()
    singleitem = session.query(Items).filter_by(name=item_name).one()
    return jsonify(SingleItem=singleitem.serializable)

# Create a new user and add to database


def createUser(login_session):
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

# Obtain user id from email


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except BaseException:
        return None

# Obtain single user info from user id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

# The default page is the catalog page for this app


@app.route('/')
@app.route('/catalog', methods=['GET'])
def showCatalog():
    # All category fields are obtained from the database and listed here.
    category = session.query(Category)
    #  Only five items that were latest added are seen in the items category
    items = session.query(Items).order_by("Items.created_date desc").limit(5)
    if 'username' not in login_session:
        # In the public catalog the options to add or remove are not included.
        return render_template(
            'publiccatalog.html',
            category=category,
            items=items)
    else:
        return render_template('catalog.html', category=category, items=items)

# The page is to add a new catergory item to the database


@app.route('/catalog/additem', methods=['GET', 'POST'])
def newItem():
    if request.method == 'POST':
        # Check if the category exists
        is_category = session.query(Category).filter_by(
            name=request.form['category']) .scalar()
        # Add the catergory if it does not exists
        if is_category is None:
            new_category = Category(
                name=request.form['category'])
                # user_id=login_session['user_id'])
            session.add(new_category)
            session.commit()
        # Retrieve info for specific category
        category = session.query(Category).filter_by(
            name=request.form['category']).one()
        # Add item details with the specific category information retrieved
        item = Items(
            name=request.form['name'],
            description=request.form['description'],
            category_id=category.id,
            user_id=login_session['user_id'])
        # Modification is made to the database
        session.add(item)
        session.commit()
        # Message that shows an item has been created
        flash("A new item has been created")
        # Upon commiting an the app returns to the default catalog page
        return redirect(url_for('showCatalog'))
    else:
        # Page to enter to new item is rendered
        return render_template('newItem.html')

# Items from a specific category is retrieved


@app.route('/catalog/<string:category_name>/items', methods=['GET', 'POST'])
# Takes input for category_name as input to retrieve information
def showItems(category_name):
    category = session.query(Category)
    # The relevant category is filtered from the category_name input
    specific_category = session.query(
        Category).filter_by(name=category_name).one()
    # All items from the specific category are retrieved
    category_items = session.query(Items).filter_by(
        category_id=specific_category.id).all()
    # All items are counted in the specific category
    category_items_count = session.query(Items).filter_by(
        category_id=specific_category.id).count()
    # Page containing information for the category and its respective items
    # are rendered
    return render_template(
        'categoryitems.html',
        category=category,
        category_items=category_items,
        category_name=specific_category.name,
        category_items_count=category_items_count)

# Item details of a specific item in the category is retrieved


@app.route(
    '/catalog/<string:category_name>/<string:item_name>',
    methods=[
        'GET',
        'POST'])
def showDetails(category_name, item_name):
    # The relevant category is filtered from the category_name input
    category = session.query(Category).filter_by(name=category_name).one()
    # All items in the category are listed
    item = session.query(Items).filter_by(category_id=category.id).all()
    # The specific item is filtered from the item_name input
    specific_item = session.query(Items).filter_by(name=item_name). one()
    creator = getUserInfo(specific_item.user_id)
    # If item is not created by the user then a public page is rendered that
    # displays item description
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template(
            'publicitemdetail.html',
            item_name=item_name,
            item_description=specific_item.description,
            category_name=category_name,
            creator=creator)
    # Over here item description is displayed along with options to modify
    # information and details
    else:
        return render_template(
            'itemdetail.html',
            item_name=item_name,
            item_description=specific_item.description,
            category_name=category_name,
            creator=creator)


# Over here the creator can edit details of the item in a category
@app.route(
    '/catalog/<string:category_name>/<string:item_name>/edit',
    methods=[
        'GET',
        'POST'])
def editItem(category_name, item_name):
    # The relevant category is filtered from the category_name input
    edit_category = session.query(Category).filter_by(name=category_name).one()
    # The specific item is filtered from the item_name input
    editeditem = session.query(Items).filter_by(
        name=item_name).one()

    if request.method == "POST":
        for key in request.form.keys():
            # Change item name
            if key == 'name' and request.form[key]:
                editeditem.name = request.form[key]
            # Change item description
            if key == 'description' and request.form[key]:
                editeditem.description = request.form[key]
            # Change item category
            if key == 'category' and request.form[key]:
                new_category = request.form[key]
                edit_new_category = session.query(
                    Category).filter_by(name=new_category).one()
                editeditem.category_id = edit_new_category.id
        # Modification made to the database
        session.add(editeditem)
        session.commit()
        # Message shown that item has been edited
        flash("Item has been edited")
        # The app returns to the default catalog page
        return redirect(url_for('showCatalog'))
    else:
        # The app renders the item edit page
        return render_template(
            'edititem.html',
            editeditem=editeditem,
            category_name=category_name,
            item_name=item_name)


# Over here the creator can delete item in a category
@app.route(
    '/catalog/<string:category_name>/<string:item_name>/delete',
    methods=[
        'GET',
        'POST'])
def deleteItem(category_name, item_name):
    # The relevant category is filtered from the category_name input
    delete_category = session.query(
        Category).filter_by(name=category_name).one()
    # The specific item is filtered from the item_name input
    deleteditem = session.query(Items).filter_by(
        category_id=delete_category.id, name=item_name).one()
    if request.method == "POST":
        # Modification is made to the database
        session.delete(deleteditem)
        session.commit()
        # Message shown that item has been deleted
        flash("Item has been deleted")
        # The app returns to the default catalog page
        return redirect(url_for('showCatalog'))
    else:
        # The app renders the item delete page
        return render_template(
            'deleteitem.html',
            category_name=category_name,
            item_name=item_name)

# Disconnect based on provider


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
