#!/usr/bin/env python

# ---
# An application by Cristi Constantin,
# E-mail : cristi.constantin@live.com,
# Blog : http://cristi-constantin.com.
# ---

import os, sys
import platform
import json
import binascii as ba
from pbkdf2 import PBKDF2

from bottle import default_app, run, route, get, post, debug
from bottle import response, request, template, static_file

BASE_PATH = os.path.dirname(__file__)

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

# # # # # # # # #
# Preparing XINHA
# # # # # # # # #
@route('/js/modules/CreateLink/dialog.html')
def d1():
    return template('js/modules/CreateLink/dialog.html')

@route('/js/modules/InsertImage/dialog.html')
def d2():
    return template('js/modules/InsertImage/dialog.html')

@route('/js/modules/InsertTable/dialog.html')
def d3():
    return template('js/modules/InsertTable/dialog.html')

@route('/js/plugins/SuperClean/dialog.html')
def d4():
    return template('js/plugins/SuperClean/dialog.html')

@route('/js/popups/editor_help.html')
def help():
    return template('js/popups/editor_help.html')

@route('/js/modules/AboutBox/dialog.html')
def about():
    return template('js/modules/AboutBox/dialog.html')

@route('/editor')
@route('/editor/')
def xinha():
    return template('Xinha.htm')
# # # # # # # # #
# End of XINHA
# # # # # # # # #

@post('/jqXHR/s')
def ajax_call_s():
    #
    if not request.header.get('X-Requested-With') == 'XMLHttpRequest':
        return
    global SITE
    SITE = request.forms.get('val', '')
    resp = {'message': generatePassword()}
    response.content_type = 'application/json; charset=UTF-8'
    return json.dumps(resp)
    #

@post('/jqXHR/p')
def ajax_call_p():
    #
    if not request.header.get('X-Requested-With') == 'XMLHttpRequest':
        return
    global PWD
    PWD = request.forms.get('val', '')
    resp = {'message': generatePassword()}
    response.content_type = 'application/json; charset=UTF-8'
    return json.dumps(resp)
    #

# Grafical password.
@post('/jqXHR/g')
def ajax_call_g():
    #
    if not request.header.get('X-Requested-With') == 'XMLHttpRequest':
        return
    global SITE, PWD
    colors = request.forms.get('val', '')
    PWD = ' '.join(['0' if x == 'ffffff' else x for x in colors.split()])
    SITE = ' '.join(['0' if x != 'ffffff' else 'fff' for x in colors.split()])
    resp = {'message': generatePassword(25)}
    response.content_type = 'application/json; charset=UTF-8'
    return json.dumps(resp)
    #

def generatePassword(size=0):
    global SITE, PWD
    if not size:
        size = len(PWD)
    if not SITE or not PWD: return ''
    txt = PBKDF2(passphrase=PWD, salt=SITE, iterations=1024).read(size*2)
    return ba.b2a_base64(txt)[:size]

#

if platform.system().lower()=='windows':
    debug(True)
    run(host='localhost', port=333, reloader=True)
else:
    path = '/home/croqqq/pwd_gen'
    if path not in sys.path:
        sys.path.append(path)
    application = default_app()
