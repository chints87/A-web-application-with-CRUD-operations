# Sports Catalog 
The web application comprises of two databases, one which stores sport categories and relevant item information and another information about users
***
### Installation 
Clone the Github repository from the following steps: 
```
$git clone https://github.com/chints87/catalog.git *name of folder*
$cd *name of folder*
```
### Usage

1) Using SQLAlchemy, create a database with tables for category, items , users and respective JSON endpoints. 

2) Using [Flask] https://pypi.org/project/Flask/1.0.2/ import tables from the created database. 

3) Generate a token state to prevent anti-forgery attacks.

```python
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # html page is generated with a token 
    return render_template('login.html', STATE=state)
```

4) Using Google APIs [https://console.developers.google.com/apis?pli=1] and Facebook APIs[https://developers.facebook.com/], to generate 'Client ID' and 'Client Secret' for the
   web application to enable a user to gain secure access.

5) Add *jquery* script to the *login.html* file.   
```javascript   
	<script src="//ajax.googleapis.com/ajax/libs/jquery/1.8.2/jquery.min.js"></script>
```

6) For each user of the system, ensure only the creators of that information are able to modify.

7) Given the web application function, develop a web server to perform on user requests.

8) For each path - derived from a wireframe - and depending on its objective, take requests to make database queries.
   Also, create templates for each path and condition dependencies to open respective pages.

9) For each page, perform CRUD operations, using data generated from database queries. 

10) Public users can browse information, but ensure no editing capabilites are active in this mode.

### Acknowledgment 

Some code here has been used, referred to or modified from the following:

1) [Udacity](https://mena.udacity.com/)
2) [github](https://github.com/)
3) [Stackoverflow](https://stackoverflow.com/)