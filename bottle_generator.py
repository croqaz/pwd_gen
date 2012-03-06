#!/usr/bin/env python

# ---
# An application by Cristi Constantin,
# E-mail : cristi.constantin@live.com,
# Blog : http://cristi-constantin.com.
# ---

import os, sys
import platform
import webbrowser

import json
import binascii as ba
import cStringIO as IO
from pbkdf2 import PBKDF2

from bottle import default_app, run, route, post, debug
from bottle import response, request, template, static_file

BASE_PATH = os.path.dirname(__file__) or os.getcwd()

SITE = ''
PWD = ''

@route(':filename#.*\.png|.*\.gif|.*\.jpg|.*\.css|.*\.js#')
def server_static(filename=None, what=None):
    return static_file(filename, root=BASE_PATH)

@route('/')
@route('/index')
@route('/index/')
@route('/home')
@route('/home/')
def home():
    return template(BASE_PATH + '/template.htm')

# Text site name
@post('/jqXHR/s')
def ajax_call_s():
    #
    if not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return 'Invalid XMLHttpRequest!'
    global SITE
    SITE = request.forms.get('val', '')
    resp = {'message': generatePassword()}
    response.content_type = 'application/json; charset=UTF-8'
    return json.dumps(resp)
    #

# Text password
@post('/jqXHR/p')
def ajax_call_p():
    #
    if not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return 'Invalid XMLHttpRequest!'
    global PWD
    PWD = request.forms.get('val', '')
    resp = {'message': generatePassword()}
    response.content_type = 'application/json; charset=UTF-8'
    return json.dumps(resp)
    #

# Grafical password
@post('/jqXHR/g')
def ajax_call_g():
    #
    if not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return 'Invalid XMLHttpRequest!'
    global SITE, PWD
    colors = request.forms.get('val', '')
    PWD = ' '.join(['0' if x == 'ffffff' else x for x in colors.split()])
    SITE = ' '.join(['0' if x != 'ffffff' else 'fff' for x in colors.split()])
    resp = {'message': generatePassword(24)}
    response.content_type = 'application/json; charset=UTF-8'
    return json.dumps(resp)
    #

# Helper function
def generatePassword(size=0):
    global SITE, PWD
    SITE = SITE.strip()
    PWD = PWD.strip()
    if not SITE or not PWD: return ''
    if not size:
        size = len(PWD)
    if size > 24:
        size = 24
    txt = PBKDF2(passphrase=PWD, salt=SITE, iterations=1024).read(size*2)
    return ba.b2a_base64(txt)[:size]

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if __name__ == '__main__':

    if platform.system().lower()=='windows':
        debug(True)
        webbrowser.open_new_tab('http://localhost:333/')
        run(host='localhost', port=333, reloader=False)
    else:
        path = '/home/croqqq/pwd_gen'
        if path not in sys.path:
            sys.path.append(path)
        application = default_app()
