#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright © 2016-2017, Okta, Inc.
# 
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import os
import re
import uuid

from flask import Flask
from flask import render_template
from flask import request
from flask import url_for
# from flask_socketio import SocketIO
# from flask_socketio import emit
import flask
import requests
import json

app = Flask(__name__)
# socketio = SocketIO(app)

appPort = None
if 'APP_PORT' in os.environ:
    appPort = int(os.environ['APP_PORT'])

if appPort is None or appPort == "":
    appPort = 5000

if 'SSL_CERT' in os.environ:
    ssl_cert = os.environ['SSL_CERT']
else:
    ssl_cert = 'ssl/server.crt'

if 'SSL_KEY' in os.environ:
    ssl_key = os.environ['SSL_KEY']
else:
    ssl_key = 'ssl/server.key'

# Configuration for forming the REST Call
pythonRequestsVersion = requests.__version__
userAgentVersion = "0.0.1"
itemType = "UserAPITool"
userAgentString = "SigSci-%s-SCIM/%s (PythonRequests %s)" \
    % (itemType, userAgentVersion, pythonRequestsVersion)


def prettyJson(data):
    return(json.dumps(data, indent=4, separators=(',', ': ')))

# Definition for error handling on the response code
def checkResponse(code, responseText, url=None, token=None, data=None):
    if code == 400:
        responseJson = json.loads(responseText)
        if "message" in responseJson and \
            (responseJson["message"] == "Parameter exists" or
             responseJson["message"] == "URL path exists" or
             responseJson["message"] == "Already exists"):
            print("Entry already exists, going to next")
        else:
            print("Bad API Request (ResponseCode: %s)" % (code))
            print("ResponseError: %s" % responseText.rstrip())
            print('url: %s' % url)
            print('email: %s' % email)
            print('Corp: %s' % corp)
            print('SiteName: %s' % site)
            print("Token: %s" % apiToken)
            print("Payload: %s" % data)
            if showPassword is True:
                print('apiToken: %s' % apiToken)
            exit(code)
    elif code == 500:
        print("Caused an Internal Server error (ResponseCode: %s)" % (code))
        print("ResponseError: %s" % responseText.rstrip())
        print('url: %s' % url)
        print('email: %s' % email)
        print('Corp: %s' % corp)
        print('SiteName: %s' % site)
        print("Token: %s" % apiToken)
        if showPassword is True:
            print('apiToken: %s' % apiToken)
        exit(code)
    elif code == 401:
        print("Unauthorized, likely bad credentials or site configuration, or"
              "lack of permissions (ResponseCode: %s)" % (code))
        print("ResponseError: %s" % responseText.rstrip())
        print('email: %s' % email)
        print('Corp: %s' % corp)
        print('SiteName: %s' % site)
        if showPassword is True:
            print('apiToken: %s' % apiToken)
        exit(code)
    elif code >= 402 and code <= 599 and code != 500:
        print("ResponseCode: %s" % code)
        print("ResponseError: %s" % responseText.rstrip())
        print('url: %s' % url)
        print('email: %s' % email)
        print('Corp: %s' % corp)
        print('SiteName: %s' % site)
        print("Token: %s" % apiToken)
        if showPassword is True:
            print('apiToken: %s' % apiToken)
        exit(code)
    else:
        print("\nSuccess")
        print("ResponseCode: %s" % code)
        print('url: %s' % url)


def doRequest(curUrl, curHeaders, curPayload=None, curMethod="GET"):
    if curMethod == "PATCH":
        response_raw = requests.patch(curUrl, headers=curHeaders, json=curPayload)
    elif curMethod == "POST":
        response_raw = requests.post(curUrl, headers=curHeaders, json=curPayload)
    elif curMethod == "GET":
        response_raw = requests.get(curUrl, headers=curHeaders, json=curPayload)
    elif curMethod == "DELETE":
        response_raw = requests.delete(curUrl, headers=curHeaders, json=curPayload)
    else:
        print("Unrecognized METHOD for request")
        exit()
    responseCode = response_raw.status_code
    responseError = response_raw.text

    return(responseCode, responseError, response_raw)

# useful for outputting correctly
class ListResponse():
    def __init__(self, list, start_index=1, count=None, total_results=0):
        self.list = list
        self.start_index = start_index
        self.count = count
        self.total_results = total_results

    def to_scim_resource(self):
        rv = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": self.total_results,
            "startIndex": self.start_index,
            "Resources": []
        }
        resources = []
        for item in self.list:
            resources.append(item.to_scim_resource())
        if self.count:
            rv['itemsPerPage'] = self.count
        rv['Resources'] = resources
        return rv


class sigsci_api:
    def __init__(self, payload=None):
        self.corp = request.headers.get("x-api-corp")
        self.api_user = request.headers.get('x-api-user')
        self.api_token = request.headers.get('x-api-token')
        self.payload = payload
        self.api_host = 'https://dashboard.signalsciences.net'
        self.users = []
        self.last_statusCode = None
        self.last_error = None
        self.headers = None


    def connectSigsci(self):
        sigsci_email = self.api_user
        sigsci_apiToken = self.api_token
        sigsci_corp = self.corp
        if sigsci_email is None or sigsci_apiToken is None or sigsci_corp is None:
            return("Access Denied", 401)
        else:
            sigsci_headers = {
                'Content-type': 'application/json',
                'x-api-user': sigsci_email,
                'x-api-token': sigsci_apiToken,
                'User-Agent': userAgentString
            }
            self.headers = sigsci_headers
            rCode, rMsg = self.get_corps()
            if rCode == 200:
                self.last_statusCode = 200
                return(self)
            else:
                self.last_statusCode = rCode
                self.last_error = rMsg
                return(rMsg, 401)

    def get_corps(self):
        corp = self.corp
        url = self.api_host + ('/api/v0/corps/%s' % (corp))
        rCode, rError, response = doRequest(url, self.headers)
        jsonResult = json.loads(response.text)
        if rCode == 200:
            return(rCode, "Success")
        else:
            return(401, rError)

    def get_memberships(self, newURL):
        corp = self.corp
        url = self.api_host + newURL
        rCode, rError, response = doRequest(url, self.headers)
        jsonResult = json.loads(response.text)
        self.last_statusCode = rCode
        self.last_error = rError
        siteList = []
        if rCode == 200:
            for memSite in jsonResult["data"]:
                siteList.append(memSite["site"]["name"])
            return(siteList)
        else:
            if "message" in jsonResult:
                self.last_error = jsonResult["message"]
                return(jsonResult["message"])
            else:
                return("Unknown Error")


    def get_users(self):
        corp = self.corp
        url = self.api_host + ('/api/v0/corps/%s/users' % (corp))
        rCode, rError, response = doRequest(url, self.headers)
        jsonResult = json.loads(response.text)
        self.last_statusCode = rCode
        self.last_error = rError
        if rCode == 200:
            for curUser in jsonResult["data"]:
                # print(prettyJson(curUser))
                user_id = curUser["email"]
                user_name = curUser["email"]
                user_email = curUser["email"]
                if curUser["status"] == "active":
                    user_active = True
                else:
                    user_active = False
                parts = curUser["name"].split()
                if len(parts) > 1:
                    user_givenName = parts[0]
                    user_familyName = parts[1]
                else:
                    user_givenName = curUser["name"]
                    user_familyName = ""
                user_role = curUser["role"]
                memberships = self.get_memberships(curUser["memberships"]["uri"])
                curUser["sites"] = memberships
                user_sites = memberships
                userObject = sigsci_user(user_id,
                                         user_active,
                                         user_name,
                                         user_givenName,
                                         user_familyName,
                                         user_email,
                                         user_role,
                                         user_sites
                )
                self.users.append(userObject)
            return(self.users)
        else:
            return("Error getting users")

    def get_user(self, email):
        corp = self.corp
        url = self.api_host + ('/api/v0/corps/%s/users/%s' % (corp, email))
        rCode, rError, response = doRequest(url, self.headers)
        jsonResult = json.loads(response.text)
        self.last_statusCode = rCode
        self.last_error = rError
        if rCode == 200:
            user_id = jsonResult["email"]
            user_name = jsonResult["email"]
            user_email = jsonResult["email"]
            if jsonResult["status"] == "active":
                user_active = True
            else:
                user_active = False
            parts = jsonResult["name"].split()
            if len(parts) > 1:
                user_givenName = parts[0]
                user_familyName = parts[1]
            else:
                user_givenName = jsonResult["name"]
                user_familyName = ""
            user_role = jsonResult["role"]
            memberships = self.get_memberships(jsonResult["memberships"]["uri"])
            jsonResult["sites"] = memberships
            user_sites = memberships
            userObject = sigsci_user(user_id,
                                     user_active,
                                     user_name,
                                     user_givenName,
                                     user_familyName,
                                     user_email,
                                     user_role,
                                     user_sites
            )
            return(userObject)
        else:
            if "message" in jsonResult:
                self.last_error = jsonResult["message"]
                return(jsonResult["message"])
            else:
                return("Unknown Error")

    def add_user(self, email, role, sites):
        corp = self.corp
        url = self.api_host + ('/api/v0/corps/%s/users/%s/invite' % (corp, email))
        if not (role == "corpOwner" or role == "corpAdmin" or role == "corpUser"
                or role == "corpObserver"):
                self.last_error = "Invalid Role"
                self.last_statusCode = 400
                errorResult = { "code": 400, "message": "Invalid Role specified"}
                return(errorResult)

        payload = {
            "role": role,
            "memberships": {
                "data": []
            }
        }

        for newSite in sites:
            newVal = { 
                "site": {
                    "name": newSite
                }
            }
            payload["memberships"]["data"].append(newVal)

        # print(prettyJson(payload))
        # exit()
        rCode, rError, response = doRequest(url, self.headers,
                                            curPayload=payload,
                                            curMethod="POST")
        self.last_statusCode = rCode
        self.last_error = rError
        if rCode == 200:
            jsonResult = json.loads(response.text)
            user_id = jsonResult["email"]
            user_name = jsonResult["email"]
            user_email = jsonResult["email"]
            user_active = False
            user_givenName = ""
            user_familyName = ""
            user_role = jsonResult["role"]
            memberships = self.get_memberships(jsonResult["memberships"]["uri"])
            jsonResult["sites"] = memberships
            user_sites = memberships
            userObject = sigsci_user(user_id,
                                         user_active,
                                         user_name,
                                         user_givenName,
                                         user_familyName,
                                         user_email,
                                         user_role,
                                         user_sites
                )
            return(userObject)
        else:
            errorResult = {"code": rCode, "message": rError}
            return(errorResult)
    def update_user(self, email, role, sites):
        corp = self.corp
        url = self.api_host + ('/api/v0/corps/%s/users/%s/invite' % (corp, email))
        if not (role == "corpOwner" or role == "corpAdmin" or role == "corpUser"
                or role == "corpObserver"):
                self.last_error = "Invalid Role"
                return("Invalid Role specified")

        payload = {
            "role": role,
            "memberships": {
                "data": []
            }
        }

        for newSite in sites:
            newVal = { 
                "site": {
                    "name": newSite
                }
            }
            payload["memberships"]["data"].append(newVal)

        # print(prettyJson(payload))
        # exit()
        rCode, rError, response = doRequest(url, self.headers,
                                            curPayload=payload,
                                            curMethod="PATCH")
        self.last_statusCode = rCode
        self.last_error = rError
        if rCode == 200:
            jsonResult = json.loads(response.text)
            user_id = jsonResult["email"]
            user_name = jsonResult["email"]
            user_email = jsonResult["email"]
            if jsonResult["status"] == "active":
                user_active = True
            else:
                user_active = False
            parts = jsonResult["name"].split()
            if len(parts) > 1:
                user_givenName = parts[0]
                user_familyName = parts[1]
            else:
                user_givenName = jsonResult["name"]
                user_familyName = ""
            user_role = jsonResult["role"]
            memberships = self.get_memberships(jsonResult["memberships"]["uri"])
            jsonResult["sites"] = memberships
            user_sites = memberships
            userObject = sigsci_user(user_id,
                                     user_active,
                                     user_name,
                                     user_givenName,
                                     user_familyName,
                                     user_email,
                                     user_role,
                                     user_sites
            )
            return(userObject)
        else:
            errorResult = {"code": rCode, "message": rError}

    def delete_user(self, email):
        corp = self.corp
        url = self.api_host + ('/api/v0/corps/%s/users/%s' % (corp, email))
        rCode, rError, response = doRequest(url, self.headers, curMethod="DELETE")
        self.last_statusCode = rCode
        self.last_error = rError
        if rCode == 204:
            return("User %s Deleted" % email)
        else:

            try:
                jsonResult = json.loads(response.text)
            except:
                jsonResult = None

            if jsonResult is not None and "message" in jsonResult:
                errorResult = {"code": rCode, "message": jsonResult["message"]}
                return(errorResult)
            else:
                errorResult = {"code": rCode, "message": "Unknown error deleting user"}
                return(errorResult)

class sigsci_user:
    def __init__(self, uid, active, uName, gName, fName, uEmail, role, sites):
        if role == "owner":
            role = "corpOwner"
        elif role == "admin":
            role = "corpAdmin"
        elif role == "user":
            role = "corpUser"
        elif role == "observer":
            role = "corpObserver"
        self.id = uid
        self.active = active
        self.userName = uName
        self.familyName = fName
        self.givenName = gName
        self.email = uEmail
        self.role = role
        self.sites = sites


    def to_scim_resource(self):
        rv = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": self.id,
            "userName": self.userName,
            "name": {
                "familyName": self.familyName,
                "givenName": self.givenName,
            },
            "role": self.role,
            "sites": self.sites,
            "active": self.active,
            "meta": {
                "resourceType": "User",
                "location": url_for('user_get',
                                    user_id=self.id,
                                    _external=True),
                # "created": "2010-01-23T04:56:22Z",
                # "lastModified": "2011-05-13T04:42:34Z",
            }
        }
        return rv


def scim_error(message, status_code=500):
    rv = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "detail": message,
        "status": str(status_code)
    }
    return flask.jsonify(rv), status_code


def send_to_browser(obj):
    socketio.emit('user',
                  {'data': obj},
                  broadcast=True,
                  namespace='/test')


def render_json(obj):
    rv = obj.to_scim_resource()
    # send_to_browser(rv)
    return flask.jsonify(rv)



@app.route('/')
def hello():
    sigsci = sigsci_api()
    sigsci.connectSigsci()
    if sigsci.last_statusCode != 200:
        return scim_error(sigsci.last_error, 401)
    else:
        return render_template('base.html')


@app.route("/scim/v2/Users/<user_id>", methods=['GET'])
def user_get(user_id):
    sigsci = sigsci_api()
    sigsci.connectSigsci();
    if sigsci.last_statusCode != 200:
        return scim_error(sigsci.last_error, 401)

    user = sigsci.get_user(user_id)
    if sigsci.last_statusCode == 200:
        return render_json(user)
    else:
        return scim_error("User not found", 404)


@app.route("/scim/v2/Users", methods=['POST'])
def users_post():
    # Create the user
    sigsci = sigsci_api()
    sigsci.connectSigsci()
    if sigsci.last_statusCode != 200:
        return scim_error(sigsci.last_error, 401)

    userJson = request.get_json(force=True)
    newUser = userJson["userName"]
    newRole = userJson["role"]
    newSites = userJson["sites"]
    user = sigsci.add_user(newUser, newRole, newSites)
    if sigsci.last_statusCode != 200:
        return(user["message"], user["code"])
    else:
    # Output in scim format
        rv = user.to_scim_resource()
        send_to_browser(rv)
        resp = flask.jsonify(rv)
        resp.headers['Location'] = url_for('user_get',
                                           user_id=user.userName,
                                           _external=True)
        return resp, 201


@app.route("/scim/v2/Users/<user_id>", methods=['PUT'])
def users_put(user_id):
    # Delete the USER
    sigsci = sigsci_api()
    sigsci.connectSigsci();
    if sigsci.last_statusCode != 200:
        return scim_error(sigsci.last_error, 401)

    user = sigsci.get_user(user_id)
    delUser = sigsci.delete_user(user_id)
    if sigsci.last_statusCode == 204:
        user.active = False
        return render_json(user)
    else:
        errorMsg = "Failed to put user %s" % user_id
        errorResult = {"message": errorMsg, "sigsci-message": sigsci.last_error}
        return(errorResult, 400)


@app.route("/scim/v2/Users/<user_id>", methods=['PATCH'])
def users_patch(user_id):
    # Update Single User
    sigsci = sigsci_api()
    sigsci.connectSigsci()
    if sigsci.last_statusCode != 200:
        return scim_error(sigsci.last_error, 401)

    patch_resource = request.get_json(force=True)
    userJson = request.get_json(force=True)
    newUser = userJson["userName"]
    newRole = userJson["role"]
    newSites = userJson["sites"]
    user = sigsci.add_user(newUser, newRole, newSites)
    if sigsci.last_statusCode != 200:
        return(user["message"], user["code"])
    else:
        return render_json(user)


@app.route("/scim/v2/Users", methods=['GET'])
def users_get():
    #request_filter = request.args.get('filter')
    sigsci = sigsci_api()
    sigsci.connectSigsci()
    if sigsci.last_statusCode != 200:
        return scim_error(sigsci.last_error, 401)

    allUsers = sigsci.get_users()
    start_index = 1
    count=100
    total_results=len(allUsers)
    rv = ListResponse(allUsers,
                      start_index=start_index,
                      count=count,
                      total_results=total_results)
    return flask.jsonify(rv.to_scim_resource())


@app.route("/scim/v2/Groups", methods=['GET'])
def groups_get():
    sigsci = sigsci_api()
    sigsci.connectSigsci()
    if sigsci.last_statusCode != 200:
        return scim_error(sigsci.last_error, 401)

    rv = ListResponse([])
    return flask.jsonify(rv.to_scim_resource())

# Next two functions were for demo purposes only and should never be used in 
# a real environment.

# @app.route('/exit', methods=['GET'])
# def exit_app():
#     print("Exit called, exiting")
#     exit(0)

if __name__ == "__main__":
    app.debug = True
    app.run(
        host='0.0.0.0',
        port=appPort,
        ssl_context=(ssl_cert, ssl_key)
        )
    
    # socketio.run(app,
    #              host='0.0.0.0',
    #              port=appPort,
    #              ssl_context=(ssl_cert, ssl_key)
    #              )
    # socketio.run(app,
    #              host='0.0.0.0',
    #              port=appPort
    #              )
