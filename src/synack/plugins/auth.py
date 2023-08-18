"""plugins/auth.py

Functions related to handling and checking authentication.
"""

import pyotp
import re
from selenium import webdriver
from time import sleep

from .base import Plugin


class Auth(Plugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for plugin in ['Api', 'Db', 'Users']:
            setattr(self,
                    plugin.lower(),
                    self.registry.get(plugin)(self.state))

    def build_otp(self):
        """Generate and return a OTP."""
        totp = pyotp.TOTP(self.db.otp_secret)
        totp.digits = 7
        totp.interval = 10
        totp.issuer = 'synack'
        return totp.now()

    def get_api_token(self):
        """Log in to get a new API token."""
        if self.users.get_profile():
            return self.db.api_token
        csrf = self.get_login_csrf()
        progress_token = None
        grant_token = None
        duo_URL = None
        if csrf:
            Duo_URL = self.get_login_progress_token(csrf)
        if Duo_URL:
            progress_token = self.get_progress_token(Duo_URL)
        if progress_token:
            grant_token = self.get_login_grant_token(csrf, progress_token)
        if grant_token:
            url = 'https://platform.ks-fedprod.synack.com/'
            headers = {
                'X-Requested-With': 'XMLHttpRequest'
            }
            query = {
                "grant_token": grant_token
            }
            res = self.api.request('GET',
                                   url + 'token',
                                   headers=headers,
                                   query=query)
            if res.status_code == 200:
                j = res.json()
                self.db.api_token = j.get('access_token')
                self.set_login_script()
                return j.get('access_token')

    def get_progress_token(self,Duo_URL):
        """Gets Duo to conduct 2FA and retrieves ProgressToken from Accept Terms URL"""
        #Sets up Selenium Webdriver options
        options = webdriver.FirefoxOptions()
        options.add_argument(Duo_URL)

        #Runs Firefox browser with Duo URL
        firefoxDriver = webdriver.Firefox(options=options)

        #Begins checking for the Accept Terms webpage
        while True:
            #This checkURL should sit on Duo URL until User accepts the login connection on Mobile
            checkURL = firefoxDriver.current_url
            if 'accept-terms' in checkURL:
                #Found Accept Terms Webpage and pulls token from URL
                ProgressToken = checkURL.split("token=",1)[1]
                break
            sleep(1)
        #Waits 3 seconds before closing Firefox browser
        sleep(3)
        firefoxDriver.quit()
        #Returns the ProgressToken to continue authentication
        return ProgressToken

    def get_login_csrf(self):
        """Get the CSRF Token from the login page"""
        res = self.api.request('GET', 'https://login.ks-fedprod.synack.com')
        m = re.search('<meta name="csrf-token" content="([^"]*)"',
                      res.text)
        return m.group(1)

    def get_login_grant_token(self, csrf, progress_token):
        """Get grant token from authy totp verification"""
        headers = {
            'X-Csrf-Token': csrf
        }
        data = {
            #"authy_token": self.build_otp(), #No longer needed
            "progress_token": progress_token
        }
        res = self.api.login('POST',
                             'authenticate',
                             headers=headers,
                             data=data)
        if res.status_code == 200:
            return res.json().get("grant_token")

    def get_login_progress_token(self, csrf):
        """Get progress token from email and password login"""
        headers = {
            'X-CSRF-Token': csrf
        }
        data = {
            'email': self.db.email,
            'password': self.db.password
        }
        res = self.api.login('POST',
                             'authenticate',
                             headers=headers,
                             data=data)
        if res.status_code == 200:
            return res.json().get("duo_auth_url")

    def get_notifications_token(self):
        """Request a new Notifications Token"""
        res = self.api.request('GET', 'users/notifications_token')
        if res.status_code == 200:
            j = res.json()
            self.db.notifications_token = j['token']
            return j['token']

    def set_login_script(self):
        script = "let forceLogin = () => {" +\
            "const loc = window.location;" +\
            "if(loc.href.startsWith('https://login.ks-fedprod.synack.com/')) {" +\
            "loc.replace('https://platform.ks-fedprod.synack.com');" +\
            "}};" +\
            "(function() {" +\
            "sessionStorage.setItem('shared-session-com.synack.accessToken'" +\
            ",'" +\
            self.db.api_token +\
            "');" +\
            "setTimeout(forceLogin,60000);" +\
            "let btn = document.createElement('button');" +\
            "btn.addEventListener('click',forceLogin);" +\
            "btn.style = 'margin-top: 20px;';" +\
            "btn.innerText = 'SynackAPI Log In';" +\
            "btn.classList.add('btn');" +\
            "btn.classList.add('btn-blue');" +\
            "document.getElementsByClassName('onboarding-form')[0]" +\
            ".appendChild(btn)}" +\
            ")();"
        with open(self.state.config_dir / 'login.js', 'w') as fp:
            fp.write(script)

        return script
