import httplib2
import json
import requests
import httplib2
import random
import string
from flask import Flask, render_template, request, flash, redirect
from flask import jsonify, url_for
from database_setup import Base, Role, Employees, User
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import session as login_session
from flask import make_response
from functools import wraps
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


app = Flask(__name__)
CLIENT_ID = json.loads(open
                       ('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Role"
engine = create_engine('sqlite:///employee.db',
                       connect_args={'check_same_thread': False}, echo=True)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()


# creating login session

@app.route('/login')
def showlogin():
    state = ''.join(random.choice(string.ascii_uppercase +
                                  string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# creating gconnect
@app.route('/gconnect', methods=['POST'])
def gconnect():
        if request.args.get('state') != login_session['state']:
            response = make_response(json.dumps('Invalid state parameter.'),
                                     401)
            response.headers['Content-Type'] = 'application/json'
            return response

        code = request.data
        try:
            ''' Upgrade the authorization code into a credentials object'''
            oauth_flow = flow_from_clientsecrets('client_secrets.json',
                                                 scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(code)
        except FlowExchangeError:
            response = make_response(
                json.dumps('Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        ''' Check that the access token is valid.'''
        access_token = credentials.access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
               % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1])
        ''' If there was an error in the access token info, abort.'''
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'
            return response

        ''' Verify that the access token is used for the intended user.'''
        gplus_id = credentials.id_token['sub']
        if result['user_id'] != gplus_id:
            response = make_response(json.dumps("Token's user ID doesn't match"
                                                " given user ID."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        ''' Verify that the access token is valid for this app.'''
        if result['issued_to'] != CLIENT_ID:
            response = make_response(json.dumps("Token's client ID does"
                                                " not match app's."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        stored_access_token = login_session.get('access_token')
        stored_gplus_id = login_session.get('gplus_id')
        if stored_access_token is not None and gplus_id == stored_gplus_id:
            response = make_response(json.dumps("Current user is already"
                                                "connected."), 200)
            response.headers['Content-Type'] = 'application/json'
            return response

        ''' Store the access token in the session for later use.'''
        login_session['access_token'] = credentials.access_token
        login_session['gplus_id'] = gplus_id
        ''' Get user info'''
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)

        data = answer.json()

        login_session['username'] = data['name']
        # login_session['picture'] = data['picture']
        login_session['email'] = data['email']
        # see if user exit,if not create new user
        user_id = getUserID(login_session['email'])
        if not user_id:
            user_id = createUser(login_session)
        login_session['user_id'] = user_id
        output = ''
        output += '<h1>Welcome, '
        output += login_session['username']
        output += '!</h1>'
        flash("you are now logged in as %s" % login_session['username'])
        print "done!"
        return output


# creating new user
def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# getting user info
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id)
    return user


# getting user ID
def getUserID(email):
    user = session.query(User).filter_by(email=email).one()
    return user.id


# disconnect from connected user
@app.route("/GLogout")
def GDisConnect():
        access_token = login_session.get('access_token')
        if access_token is None:
            response = make_response(json.dumps('Current user not connected.'),
                                     401)
            response.headers['Content-Type'] = 'application/json'
            return response
        url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
               % access_token)
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        if result['status'] == '200':
            # Reset the user's sesson.
            del login_session['access_token']
            del login_session['gplus_id']
            del login_session['username']
            del login_session['email']
            response = make_response(json.dumps('Successfully logged out!.'),
                                     200)
            response.headers['Content-Type'] = 'application/json'
            flash('Successfully Logged Out!')
            return redirect(url_for('showrole'))
        else:
            # For whatever reason, the given token was invalid.
            response = make_response(json.dumps('Failed to revoke'
                                                'token for given user.'), 400)
            response.headers['Content-Type'] = 'application/json'
            return response


@app.route('/role/<int:role_id>/JSON')
def roleJSON(role_id):
    role = session.query(Role).filter_by(role_id=role_id).one()
    employees = session.query(Employees).filter_by(
        role_id=role_id).all()
    return jsonify(Employees=[i.serialize for i in employees])


@app.route('/role/<int:role_id>/employees/<int:emp_id>/JSON')
def employeesJSON(role_id, emp_id):
    employees = session.query(Employees).filter_by(emp_id=emp_id).one()
    return jsonify(employees=employees.serialize)


@app.route('/role/JSON')
def rolesJSON():
    role = session.query(Role).all()
    return jsonify(role=[r.serialize for r in role])


# Show all roles
@app.route('/')
@app.route('/role/')
def showrole():
    role1 = session.query(Role)
    return render_template('roles.html', r=role1)


# Create a new role
@app.route('/role/new/', methods=['GET', 'POST'])
def newrole():
    role1 = session.query(Role)
    CREATOR = getUserInfo(Role.user_id)
    if 'username' not in login_session:
        return render_template('roles.html', r=role1)
    else:
        if request.method == 'POST':
            newrole = Role(rolename=request.form['name'],
                           user_id=login_session['user_id'])
            print (newrole)
            session.add(newrole)
            session.commit()
            # session.rollback()
            return redirect(url_for('showrole'))
        else:
            return render_template('newRole.html')
    # return "This page will be for making a new role"

# Edit a role


@app.route('/role/<int:role_id>/edit/', methods=['GET', 'POST'])
def editrole(role_id):
    editedrole = session.query(Role).filter_by(role_id=role_id).one()
# edit = session.query(
# role).filter_by(role_id=role_id).one()
    role1 = session.query(Role)
    CREATOR = getUserInfo(Role.user_id)
    if 'username' not in login_session:
        flash(" this is belongs to admin")
        return render_template('roles.html', r=role1)

    else:
        if editedrole.user_id == login_session['user_id']:
            if request.method == 'POST':
                if request.form['name']:
                    editedrole.rolename = request.form['name']
                    return redirect(url_for('showrole'))
            else:
                return render_template('editRole.html', r=editedrole)
        else:
            return redirect('/')
    # return 'This page will be for editing role %s' % role_id

# Delete a role


@app.route('/role/<int:role_id>/delete/', methods=['GET', 'POST'])
def deleterole(role_id):
    roleToDelete = session.query(
        Role).filter_by(role_id=role_id).one()
    role1 = session.query(Role)
    CREATOR = getUserInfo(Role.user_id)
    if 'username' not in login_session:
        return render_template('roles.html', r=role1)
    else:
        if roleToDelete.user_id == login_session['user_id']:
            if request.method == 'POST':
                session.delete(roleToDelete)
                session.commit()
                return redirect(url_for('showrole'))
            else:
                return render_template('deleteRole.html', r=roleToDelete)
        else:
            return redirect('/')
    # return 'This page will be for deleting role %s' % role_id


# Show a dept employees
@app.route('/role/<int:role_id>/')
@app.route('/role/<int:role_id>/employees/')
def showemployees(role_id):
    roles = session.query(Role).filter_by(role_id=role_id).one()
    employee = session.query(Employees).filter_by(
        role_id=role_id).all()
    role1 = session.query(Role)
    CREATOR = getUserInfo(Role.user_id)

    return render_template('employees.html', e=employee,
                           r=roles, CREATOR=CREATOR)
# Create a new employees


@app.route(
    '/role/<int:role_id>/employees/new/', methods=['GET', 'POST'])
def newemployees(role_id):
    roles = session.query(Role).filter_by(role_id=role_id).one()
    CREATOR = getUserInfo(Role.user_id)
    employee = session.query(Employees).filter_by(
        role_id=role_id).all()
    if 'username' not in login_session:
        return render_template('employees.html', e=employee, role_id=role_id,
                               r=roles, CREATOR=CREATOR)
    else:
        if roles.user_id == login_session['user_id']:
            if request.method == 'POST':
                newemployees = Employees(name=request.form['name'],
                                         role_id=role_id)
                session.add(newemployees)
                session.commit()
                return redirect(url_for('showemployees', role_id=role_id))
            else:
                return render_template('newEmployees.html', r=role_id)
        else:
            return redirect('/role/')
# edit employee details


@app.route('/role/<int:role_id>/<int:emp_id>/edit',
           methods=['GET', 'POST'])
def editemployee(role_id, emp_id):
    editedemployee = session.query(Role).filter_by(role_id=role_id).one()
    emplist = session.query(Employees).filter_by(emp_id=emp_id).one()
    if 'username' not in login_session:
        return redirect(url_for('showemployees'))
    if editedemployee.user_id != login_session['user_id']:
        flash("permission denied")
        return redirect(url_for('showemployees', role_id=role_id))
    if request.method == 'POST':
        if request.form['name']:
            editedemployee.name = request.form['name']
            session.add(editedemployee)
            session.commit()
            return redirect(url_for('showemployees', role_id=role_id))
    else:
        return render_template('editEmployees.html', emplist=emplist,
                               emp_id=emp_id, r=editedemployee)
# Delete items


@app.route('/role/<int:role_id>/employees/<int:emp_id>/delete',
           methods=['GET', 'POST'])
def deleteemployee(role_id, emp_id):
    if 'username' not in login_session:
        return redirect(url_for('showemployees'))
    item = session.query(Employees).filter_by(emp_id=emp_id).one()
    delemp = session.query(Role).filter_by(role_id=role_id).one()
    if delemp.user_id != login_session['user_id']:
        flash("permission denied")
        return redirect(url_for('showemployees', role_id=role_id))
    if request.method == 'POST':
        session.delete(delemp)
        session.commit()
        return redirect(url_for('showemployees', role_id=role_id))
    else:
        return render_template('delEmployee.html', r=delemp,
                               emp=item, emp_id=emp_id)
if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.debug = True
    app.run(host='0.0.0.0', port=7000)
