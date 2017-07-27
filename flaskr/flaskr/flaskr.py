# all the imports
import os
import sqlite3

from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash
     
app = Flask(__name__) # create the application instance :)
app.config.from_object(__name__) # load config from this file , flaskr.py

# Load default config and override config from an environment variable
'''app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'flaskr.db'),
    SECRET_KEY='development key',
    USERNAME='admin',
    PASSWORD='default'
))'''

app.config.from_envvar('FLASKR_SETTINGS', silent=True)
from flask import render_template, flash, redirect, session, url_for, request, g
from flask.ext.login import login_user, logout_user, current_user, login_required
from flaskr import db, app, models
from flaskr.forms import LoginForm
from flaskr.models import User, ROLE_USER, ROLE_ADMIN

'''@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form('username') == 'a' and request.form('password') == 'a':
            return render_template('haha.html')
        elif request.form('username') == 'b' and request.form('password') == 'b':
            return render_template('lala.html')
    return render_template('login.html', error=error)'''

'''@app.route('/')
def index():
    if id[2]==1:
       return render_template('haha.html')
    return render_template('haha.html')'''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        form = LoginForm()
    #if form.validate_on_submit():
        #id = db.query(User.id).filter_by(username=form.username.data,password=form.password.data).count()
        #ro = db.query(role).filter_by(username=form.username.data,password=form.password.data).first()
        a = User.query.filter_by(username=form.username.data,password=form.password.data)
        if a is None:
            session['log_in'] = False
            return redirect(url_for('login'))
         #elif ro == 1:
            #return render_template('haha.html')'''
        return render_template('lala.html')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    #flash('You were logged out')
    return render_template('login.html')



