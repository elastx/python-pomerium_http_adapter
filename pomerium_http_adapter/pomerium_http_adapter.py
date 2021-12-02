'''pomerium_http_adapter - Transport adapter for requests to handle Pomerium authentication'''

# Standard library dependencies
import os
import json
import time
import glob
import base64
import urllib
import secrets
import logging
import webbrowser
import http.server

# Third-party dependencies
import requests

# Defaults and globals
_log = logging.getLogger('pomerium_http_adapter')

DEFAULT_TIME_DRIFT_SECONDS = 60
DEFAULT_CACHE_PATH = '/dev/shm/pomerium_http_adapter-%s' % os.getuid()
DEFAULT_LISTEN_PORT = 8000


# -------------------------------------------------------------------------------------------------
class _PomeriumRequestHandler(http.server.BaseHTTPRequestHandler):
    '''Request handler for processing of authentication redirects'''

    # ---------------------------------------------------------------------------------------------
    def log_message(self, format, *args):
        '''Function to override default logging in the HTTP request handler'''

        pass

    # ---------------------------------------------------------------------------------------------
    def generate_body(self, message):
        '''Generate HTML response data containing specified message'''

        _log.debug('Generating HTML response body with message "%s"' % message)

        return (
            '<html><head><title>Pomerium Transport Authentication</title></head>' +
            '<body style="font-family: monospace; background-color: #000; color: #fff;" ' +
            'onload="setTimeout(window.close, 3500);"><h1>%s</h1></body></html>' % message)

    # ---------------------------------------------------------------------------------------------
    def generate_response(self, status_code, message):
        '''Generate HTTP response with specified status code and message'''

        _log.debug(
            'Generating HTTP response with status code %i and message "%s"'
            % (status_code, message))

        self.send_response(status_code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        self.wfile.write(self.generate_body(message).encode('utf-8'))

        return

    # ---------------------------------------------------------------------------------------------
    def do_GET(self):
        '''Function for processing all GET requests to server'''

        _log.info('Processing authentication redirect request')

        parsed_url = urllib.parse.urlparse(self.path)

        if not parsed_url.path.startswith('/auth/%s' % self.server.validation_token):
            log_message = 'Received request without matching validation token'
            _log.error(log_message) 

            return self.generate_response(401, log_message)

        # -----------------------------------------------------------------------------------------
        _log.debug('Trying to extract JWT query parameter from path')

        log_message = 'Received request without valid JWT query parameter'

        if not parsed_url.query:
            _log.error(log_message) 

            return self.generate_response(401, log_message)

        parsed_query_string = urllib.parse.parse_qs(parsed_url.query, strict_parsing=True)

        if not 'pomerium_jwt' in parsed_query_string.keys():
            _log.error(log_message) 

            return self.generate_response(401, log_message)

        if not parsed_query_string['pomerium_jwt']:
            _log.error(log_message) 

            return self.generate_response(401, log_message)

        if not parsed_query_string['pomerium_jwt'][0]:
            _log.error(log_message) 

            return self.generate_response(401, log_message)

        self.server.request_jwt = parsed_query_string['pomerium_jwt'][0]

        # -----------------------------------------------------------------------------------------
        self.generate_response(200, 'Authentication successful - you may now close this tab!')
        self.server.process_requests = False

        return


# -------------------------------------------------------------------------------------------------
class _PomeriumHTTPServer(http.server.HTTPServer):
    '''HTTP server with support for passing data from handler classes'''

    # ---------------------------------------------------------------------------------------------
    def __init__(self, server_address, handler_class, validation_token):
        '''Initialization function for HTTP server'''

        self.validation_token = validation_token
        self.process_requests = True
        self.request_jwt = ''

        super().__init__(server_address, handler_class)

        return


# -------------------------------------------------------------------------------------------------
class Pomerium(object):
    '''Object which gets, expose and cache Pomerium authentication tokens'''

    # ---------------------------------------------------------------------------------------------
    def __init__(self, **kwargs):
        '''Initialization function for Pomerium authentication class'''

        # -----------------------------------------------------------------------------------------
        if 'time_drift_seconds' in kwargs.keys():
            self.time_drift_seconds = kwargs['time_drift_seconds']

        else:
            self.time_drift_seconds = DEFAULT_TIME_DRIFT_SECONDS

        if 'cache_path' in kwargs.keys():
            self.cache_path = kwargs['cache_path']

        else:
            self.cache_path = DEFAULT_CACHE_PATH

        if 'listen_port' in kwargs.keys():
            self.listen_port = kwargs['listen_port']

        else:
            self.listen_port = DEFAULT_LISTEN_PORT

        # -----------------------------------------------------------------------------------------
        if not os.path.isdir(self.cache_path):
            _log.debug('Cache directory "%s" does not exist - creating it' % self.cache_path)

            try:
                os.makedirs(self.cache_path, mode=0o0700, exist_ok=True)

            except Exception as original_exception:
                raise Exception(
                    'Failed to create Pomerium cache directory "%s":"%s"'
                    % (self.cache_path, original_exception))

        self._expiry = -1
        self._jwt = ''

        return

    # ---------------------------------------------------------------------------------------------
    def _extract_expiry(self, jwt):
        '''Parses unvalidated JWT to extract expiry time'''

        _log.debug('Extracting expiry time from JWT')
        error_message = 'Failed to get expiry time from JWT as it does not match expected format'

        if not '.' in jwt:
            raise Exception(error_message)

        jwt_parts = jwt.split('.')

        if len(jwt_parts) != 3:
            raise Exception(error_message)

        # Pomerium does not always  properly pad encoded data, so we'll add some and rely on
        # Python 3's behavior of truncating unnecessary padding
        jwt_data = jwt_parts[1] + '=='

        try:
            jwt_data_parsed = json.loads(base64.b64decode(jwt_data, validate=False))

        except Exception as original_exception:
            raise Exception('%s: "%s"' % (error_message, original_exception))

        if not type(jwt_data_parsed) is dict and not 'exp' in jwt_data_parsed.keys():
            raise Exception(error_message)

        try:
            expiry = int(jwt_data_parsed['exp'])

        except Exception as original_exception:
            raise Exception('%s: "%s"' % (error_message, original_exception))

        _log.debug('Extracted expiry time: %i' % expiry)

        return expiry

    # ---------------------------------------------------------------------------------------------
    def _store_jwt(self, jwt):
        '''Set internal variables for JWT/expiry and save to cache file'''

        cache_file = os.path.join(self.cache_path, 'pc-%i.json' % int(time.time()))
        _log.debug('Storing JWT/expiry time in variables and cache file "%s"' % cache_file)

        self._jwt = jwt
        self._expiry = self._extract_expiry(jwt)

        try:
            with open(cache_file, 'w') as file_handle:
                json.dump({'expiry': self._expiry, 'jwt': self._jwt}, file_handle, indent=2)

        except Exception as original_exception:
            raise Exception('Failed to save Pomerium JWT to cache: "%s"' % original_exception)

        return

    # ---------------------------------------------------------------------------------------------
    def authenticate(self, url):
        '''Perform authentication flow using the specified URL'''

        _log.debug('Starting authentication process using URL "%s"' % url)

        parsed_url = urllib.parse.urlparse(url)
        validation_token = secrets.token_urlsafe(16)
        query_parameters = urllib.parse.urlencode(
            {'pomerium_redirect_uri': 'http://127.0.0.1:%i/auth/%s'
            % (self.listen_port, validation_token)})

        login_url = 'https://%s/.pomerium/api/v1/login?%s'% (parsed_url.netloc, query_parameters)

        # -----------------------------------------------------------------------------------------
        _log.debug('Starting Pomerium login flow against "%s"' % login_url)
        error_message = 'Failed to query Pomerium login API for URL "%s"' % url

        try:
            login_response = requests.get(login_url)

        except Exception as original_exception:
            raise Exception('%s: "%s"' % (error_message, original_exception))

        if login_response.status_code != 200:
            raise Exception(
                '%s: Got HTTP status code %i' % (error_message, login_response.status_code))

        if not 'Content-Type' in login_response.headers.keys():
            raise Exception('%s: Server response is missing content type' % error_message)

        if not 'text/plain' in login_response.headers['Content-Type']:
            raise Exception(
                '%s: Got HTTP response with content type "%s"'
                % (error_message, login_response.headers['Content-Type']))

        if not login_response.text.startswith('https://'):
            raise Exception(
                '%s: Expected authentication URL as body, got "%s"'
                % (error_message, login_response.text))

        authentication_url = login_response.text

        # -----------------------------------------------------------------------------------------
        _log.info('Performing Pomerium authentication against "%s"' % authentication_url)

        try:
            server = _PomeriumHTTPServer(
                ('127.0.0.1', self.listen_port), _PomeriumRequestHandler, validation_token) 

        except Exception as original_exception:
            raise Exception(
                'Failed to start local listener on port %i for Pomerium authentication: "%s"'
                % (self.listen_port, original_exception))


        _log.info('Opening Pomerium authentication URL in web browser: %s' % authentication_url)
        webbrowser.open_new_tab(authentication_url)

        try:
            while server.process_requests:
                server.handle_request()

        except Exception as original_exception:
            raise Exception('Failed to process request for listener: "%s"' % original_exception)

        # Always try to close the listening socket
        try:
            server.socket.close()

        except:
            pass

        self._store_jwt(server.request_jwt)

        return

    # ---------------------------------------------------------------------------------------------
    def _reload_cache(self):
        '''Loads the latest stored JWT from cache directory'''

        _log.debug('Reloading token cache from "%s"' % self.cache_path)

        cache_files = glob.glob(os.path.join(self.cache_path, 'pc-*.json'))
        cache_files.sort()

        if not cache_files:
            _log.debug('No cache files found in "%s"' % self.cache_path)

            return

        cache_file = cache_files[-1]

        # -----------------------------------------------------------------------------------------
        _log.debug('Loading JSON data from cache file "%s"' % cache_file)

        try:
            with open(cache_file, 'r') as file_handle:
                cache = json.load(file_handle)

        except Exception as original_exception:
            raise Exception(
                'Failed to read JWT cache file "%s": "%s"' % (cache_file, original_exception))

        self._expiry = cache['expiry']
        self._jwt = cache['jwt']

        return

    # ---------------------------------------------------------------------------------------------
    def _get_jwt(self):
        '''Internal function used to return JWT'''

        # If multiple applications use the library, there may be a newer token in the cache
        if self._expiry <= (time.time() + self.time_drift_seconds):
            self._reload_cache()

        return self._jwt

    # ---------------------------------------------------------------------------------------------
    jwt = property(_get_jwt)


# -------------------------------------------------------------------------------------------------
class PomeriumHTTPAdapter(requests.adapters.HTTPAdapter):
    '''Transport adapter class for requests to handle Pomerium authentication'''

    # ---------------------------------------------------------------------------------------------
    def __init__(self, *args, **kwargs):
        '''Initialization function for Pomerium HTTP adapter'''
        
        if 'authenticated_domains' in kwargs.keys():
            self.authenticated_domains = kwargs['authenticated_domains']
            _log.debug(
                'Initializing adapter configured for authentication against domains: "%s"'
                % repr(self.authenticated_domains))

        else:
            self.authenticated_domains = []

        self.pomerium = Pomerium(**kwargs)

        # -----------------------------------------------------------------------------------------
        # Requests is picky about unknown options, so we must clear them before parent init
        for custom_option in [
            'authenticated_domains', 'time_drift_seconds', 'cache_path', 'listen_port']:

            if custom_option in kwargs.keys():
                kwargs.pop(custom_option)

        super().__init__(*args, **kwargs)

        return

    # ---------------------------------------------------------------------------------------------
    def _permit_authentication(self, url):
        '''Check if JWT authentication should be added for specified URL'''

        _log.debug('Checking if request to URL "%s" should be authenticated' % url)

        parsed_url = urllib.parse.urlparse(url)

        if not parsed_url.scheme == 'https':
            _log.debug('Authentication is only allowed for HTTPS URLs')

            return False

        if not self.authenticated_domains:
            _log.debug('No list of domains explicitly configured for authentication')

            return True

        # -----------------------------------------------------------------------------------------
        host_name = parsed_url.hostname
        _log.debug('Checking if "%s" match in list of permitted domains' % host_name)

        for authenticated_domain in self.authenticated_domains:
            _log.debug('Checking domain/domain suffix "%s"' % authenticated_domain)

            if host_name == authenticated_domain:
                _log.debug('Host name matched domain "%s"' % authenticated_domain)

                return True

            if host_name.endswith('.' + authenticated_domain):
                _log.debug(
                    'Host "%s" matched domain suffix "%s"' % (host_name, authenticated_domain))

                return True

        # -----------------------------------------------------------------------------------------
        _log.debug('Request host "%s" did not match any explicitly permitted domains' % host_name)

        return False

    # ---------------------------------------------------------------------------------------------
    def send(self, request, **kwargs):
        '''Override function to add Pomerium authentication to all targeted requests'''

        if not self._permit_authentication(request.url):
            _log.warning(
                'Not authenticating URL "%s" as it does not matched allowed domains/protocols' 
                % request.url)

            return super().send(request, **kwargs)

        # -----------------------------------------------------------------------------------------
        _log.debug('Processing Pomerium authenticated request')

        request.headers['Authorization'] = 'Pomerium %s' % self.pomerium.jwt
        response = super().send(request, **kwargs)

        _log.debug('Checking if response from request was a sign-in redirect')

        if ((response.is_redirect and '/.pomerium/sign_in?' in response.headers['Location']) or
            (response.history and response.history[0].is_redirect and
            '/.pomerium/sign_in?' in response.history[0].headers['Location'])):

            _log.debug('Authentication token seems to be invalid - force re-authenticating')

            self.pomerium.authenticate(request.url)
            request.headers['Authorization'] = 'Pomerium %s' % self.pomerium.jwt

            _log.debug('Re-sending Pomerium atuhenticated request')

            return super().send(request, **kwargs)

        return response
