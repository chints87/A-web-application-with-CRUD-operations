from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User
app = Flask(__name__) # creating an instance of this class with the name of the running application as the argument

from flask import session as login_session # like a dictionary that stores user longevity with server
import random, string

from oauth2client.client import flow_from_clientsecrets #store json formatted style clientid, clientsecret and other oauth2 parameters
from oauth2client.client import FlowExchangeError # catch error when trying to exchange an authorization code for an access token 
import httplib2 # http client lib in python 
import json # provides an API converting in memory python objects to a serialized rep. known as Json
from flask import make_response #converts return value from a function into a real response object that we can send to our client 
import requests # apache 2.0 licensed HTTP library written in python

CLIENT_ID = json.loads(
    open('client_secrets.json','r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

# engine = create_engine('sqlite:///restaurantmenu.db')
engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine

DBsession = sessionmaker(bind = engine)
session = DBsession()

# Create a state token to prevent request forgery
# Store it in the session for later validation

@app.route('/login')
def showLogin():
    #unique session token generation
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(10))
    login_session['state'] = state
    # return "%s" % login_session['state']
    return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response 
    code = request.data # collect one-time code (is that authorization code)
    try:
        # Upgrade from authorization code into a credentials object 
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope = '') # creates an oauthflow object and adds my clients secret key information to it 
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code) # passing one time code as input exchanges an authorization code for a credentials object 
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response 
    #Check that the access token is valid
    access_token = credentials.access_token # storing credentials access token in the access token variable 
    print (access_token)
   
    url = ("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}".format(access_token)) # Google API server can verify that if this is a valid token for use 
    # json GET request containing url and access token 
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # req = json.loads(h.request(url,'GET')[1])
    # req_json = req.decode('utf8').replace("'", '"')
    # result = json.loads(req_json)
    if result.get('error') is not None:
        response = make_response(json.dumps(results.get('error')), 500) # If not true then we have working access token
        response.headers['Content-Type'] = 'application.json'
        return response
    # verify if the access token is used for the intended user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match given user ID"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response 

    if result['issued_to'] != CLIENT_ID :
        response = make_response(
            json.dumps("Token's client ID does not match apps"), 401)
        print "Token's client ID does not match apps"
        response.headers['Content-Type'] = 'application/json'
        return response 

    #Check to see if user is already logged in 
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id: 
        response = make_response(json.dumps('Current user is already connected.'),200)
        response.headers['Content-Type'] = 'application/json'
        
    #Store the access token in the session for later use
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    #Get user info from the google plus api. A message is sent to the 
    # Google API server with my access token, 
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    
    # Send off message to google API with access token
    # requesting user info allowed
    # by the token scope and stored in an object called data
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    #Storing info in the login session
    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]
    

    user_id = getUserID(login_session['email'])    
    if not user_id:  
        user_id = createUser(login_session)
    login_session['user_id'] = user_id 
   


    #Create a response that knows the username and picture
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

def getUserID(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None       

def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user

def createUser(login_session):
    newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'] )
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id 

#DISCONNECT - Revoke a current user's token and reset their login_session
# This is done by telling the server to reject its access token 

@app.route("/gdisconnect")
def gdisconnect():  
    print("in gdisconnect")
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
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

    # If succesful then user info is deleted, else error message shown which is a bad request.

    if result['status'] == '200':

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/fbconnect', methods = ['POST'])    
def fbconnect(): 
    print ("in fbconnect")
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'),401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data

    #Exchange client token for long-lived server-side token with 
    #oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token={short-lived-token}'
    
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret'] # to verify server identity
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1] 
    data = json.loads(result)

    # Extract the access token from response
    token = 'access_token=' + data['access_token']   


        # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.9/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    # strip expire tag from access token since do not need it to be make API calls
    token = result.split(',')[0].split(':')[1].replace('"', '')

    # If token works, then one should be able to make API calls with the new token
    url = 'https://graph.facebook.com/v2.9/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
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
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

# Making an API endpoint (GET request)
@app.route('/restaurants/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serializable for i in items])

@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/JSON')  
def singleitemJSON(restaurant_id,menu_id):     
    singleitem = session.query(MenuItem).filter_by(id= menu_id).one()    
    return jsonify(MenuItems=singleitem.serializable)

@app.route('/restaurant/JSON')
def restaurantJSON():
    restaurant = session.query(Restaurant)
    return jsonify(Restaurant=[i.serializable for i in restaurant])


#@app.route('/') # @ is called the decorator, it wraps our function inside the app.route function that flask has already created 
                # It will call the function that follows it whenever the web server receives a request with a URL that matches its argument
                # the decorator binds the function to a url 
@app.route('/') # the app./ will call the app./hello which will call the HelloWorld function  
@app.route('/restaurants/<int:restaurant_id>/menu')
def restaurantMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id)
    return render_template('menu.html',restaurant=restaurant, items=items) # need to pass queries into the table


@app.route('/restaurant')
def showRestaurants():
    restaurants = session.query(Restaurant)
    if 'username' not in login_session:
        return render_template('publicrestaurants.html', restaurants = restaurants)
    else: 
        return render_template('restaurant.html', restaurants = restaurants)

 # Create a new restaurant


@app.route('/restaurant/new/', methods=['GET', 'POST'])
def newRestaurant():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newRestaurant = Restaurant(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newRestaurant)
        flash('New Restaurant %s Successfully Created' % newRestaurant.name)
        session.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('newRestaurant.html')

# Edit a restaurant


@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedRestaurant = session.query(
        Restaurant).filter_by(id=restaurant_id).one()    
    if request.method == 'POST':
        if request.form['name']:
            editedRestaurant.name = request.form['name']
            flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
            return redirect(url_for('showRestaurants'))
    else:
        return render_template('editRestaurant.html', restaurant_edited=editedRestaurant.name, restaurant_id = restaurant_id)


# Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurantToDelete = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        session.delete(restaurantToDelete)
        flash('%s Successfully Deleted' % restaurantToDelete.name)
        session.commit()
        return redirect(url_for('showRestaurants', restaurant_id=restaurant_id))
    else:
        return render_template('deleteRestaurant.html', restaurant_delete=restaurantToDelete.name,restaurant_id = restaurant_id)

# Show a restaurant menu


@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()    
    creator = getUserInfo(restaurant.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicmenu.html', items = items, restaurant = restaurant, creator = creator)
    else:
        return render_template('menu.html', items=items, restaurant=restaurant)   

# Create route for newMenuItem function here

@app.route('/restaurants/<int:restaurant_id>/new/', methods = ['GET','POST'])
def newMenuItem(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()    
    if request.method == 'POST':
        newItem = MenuItem(name=request.form['name'], description=request.form['description'], price=request.form[
                           'price'], course=request.form['course'], restaurant_id=restaurant_id, user_id=restaurant.user_id)
        session.add(newItem)
        session.commit()
        flash ("new menu items created!!")
        return redirect(url_for('restaurantMenu', restaurant_id = restaurant_id))
    else:
        return render_template('newMenuItem.html', restaurant_id = restaurant_id)   

@app.route('/restaurants/<int:restaurant_id>/<int:menu_id>/edit/', methods = ['GET', 'POST'])
def editMenuItem(restaurant_id,menu_id): 
    if 'username' not in login_session:
        return redirect('/login')      
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()    
    if request.method == 'POST':
        if request.form['name']:            
            editedItem.name = request.form ['name']
            session.add(editedItem)
            session.commit()
            flash("menu items edited")            
            return redirect(url_for('restaurantMenu', restaurant_id = restaurant_id))
    else:
        return render_template('editMenuItem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = editedItem)     


@app.route('/restaurants/<int:restaurant_id>/<int:menu_id>/delete/', methods = ['GET', 'POST'])
def deleteMenuItem(restaurant_id,menu_id): 
    if 'username' not in login_session:
        return redirect('\login')
    deleteItem = session.query(MenuItem).filter_by(id=menu_id).one()
    if request.method == 'POST':
        session.delete(deleteItem)
        session.commit()
        flash("menu item deleted!!")
        return redirect(url_for('restaurantMenu', restaurant_id= restaurant_id))
    else:
        return render_template('deletemenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = deleteItem)  

#Disconnect based on provider
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
        return redirect(url_for('showRestaurants'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showRestaurants'))        



if __name__ == '__main__': # application run by the python intrepreter gets a name variable set to __main__ whereas all the other
                           # imported python files get a __name__ variable set to the actual name of the python file 
    app.secret_key = 'super_secret_key' # flask will use this to create sessions for our users. This should be a very secure password if the application was live on the internet
    app.debug = True # restarting our server each time we make a modification to our code. If you enable debug support the server will load reload itself each time it notices a code change
    app.run(host = '0.0.0.0', port = 5000) # running local server with our application. Also tells the web server on my vagrant machine to listen on all public IPs
