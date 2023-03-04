from kiteconnect import KiteConnect, KiteTicker
import pyotp
import json
import logging
import requests
import urllib
from typing import Tuple, List

def get_new_access_token(kite:KiteConnect, login_info:dict): 
    """
    This method generates a new access token for the KiteConnect API. 
    
    Parameters:
    - kite (KiteConnect): An instance of the KiteConnect class.
    - login_info (dict): A dictionary containing the following keys:
        - api_key (str): The API key for the KiteConnect account.
        - userid (str): The user ID for the KiteConnect account.
        - password (str): The password for the KiteConnect account.
        - totp_key (str): The TOTP key for the KiteConnect account.
        - api_secret (str): The API secret for the KiteConnect account.
    
    Returns:
    - access_token (str): The new access token for the KiteConnect API.
    """
    
    # Create a new session using the requests library
    r = requests.Session()
    
    # Make a GET request to the KiteConnect login page and extract the session_id from the headers
    redirected_response = r.get(f"https://kite.zerodha.com/connect/login?api_key={login_info['api_key']}&v=3")
    session_id = redirected_response.url.split('sess_id=')[1]
    
    # Make a POST request to the KiteConnect login API and extract the request_id from the response
    login_result = r.post(
                'https://kite.zerodha.com/api/login',
                data={"user_id": login_info['userid'], "password": login_info['password']},
            )
    request_id = login_result.json()['data']['request_id']
    
    # Generate a TOTP using the pyotp library and pass it in a POST request to the KiteConnect 2FA API
    totp = pyotp.TOTP(login_info['totp_key'])
    totp_value = str(totp.now())
    totp_result = r.post(
                'https://kite.zerodha.com/api/twofa',
                data={
                    "user_id": login_info['userid'],
                    "request_id": request_id,
                    "twofa_value": totp_value,
                    "skip_session": "true",
                },
                allow_redirects=True
            )
    
    # Make a GET request to the KiteConnect finish page and extract the request_token from the headers
    login_finish_info = r.get(f"https://kite.zerodha.com/connect/finish?sess_id={session_id}&api_key={login_info['api_key']}")
    request_token = login_finish_info.url.split('request_token=')[1].split('&')[0]
    
    # Generate a new session using the KiteConnect instance and api_secret from the login_info dictionary
    data = kite.generate_session(request_token, api_secret=login_info['api_secret'])
    access_token = data["access_token"]
    return access_token

def get_stored_access_token(kite:KiteConnect):
    access_token = None
    ACCESS_TOKEN_FILE = "access_token.json"
    try:
        with open(ACCESS_TOKEN_FILE,'r') as f:
            access_token = json.load(f)["access_token"]
        kite.set_access_token(access_token)
        kite.profile()
    except Exception as e:
        access_token = None
    return access_token

def automated_login(kite:KiteConnect):
    """
    This function is used to automate the login process. It reads the login information from the login_info.json file, 
    sets the api_key, generates an access token and sets it, and returns the kite object, and any exceptions that were raised.
    """
    exceptions = []
    access_token = None
    try:
        # Open the login_info.json file and read the login information
        with open('login_info.json','r') as f:
            login_info = json.load(f)
        # Check if there is an access token already present and check its validity also.
        access_token = get_stored_access_token(kite) 
        # If it is not a valid access token, generate a new one.
        if access_token == None:
            access_token = get_new_access_token(kite, login_info)
        kite.set_access_token(access_token)
        kite.profile()
        # If everything works fine, write the access token into access_token.json. This doesn't cause any harm even if we are using older access token.
        with open("access_token.json",'w') as f:
            json.dump({'access_token':access_token},f)
    except Exception as e:
        exceptions.append(str(e))
    return access_token, exceptions