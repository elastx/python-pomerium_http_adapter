# pomerium_http_adapter
#### Transport adapter for requests to handle Pomerium authentication


## Introduction
This Python module acts as a "transport adapter" for the popular "requests"
library. It enables transparent Pomerium authentication (in a similar
fashion as "pomerium-cli") of HTTPS requests.


## Current status
The module is still in early development and lacks things such as a test
suite and documentation. Contributions are welcome!


## Example usage
```
import requests
import pomerium_http_adapter

session = requests.Session()
adapter = pomerium_http_adapter.PomeriumHTTPAdapter(
    authenticated_domains=['example.com'])

session.mount('https://', adapter)

for user in session.get('https://api.example.com/v2/users').json():
    print('=> %s' % user['name'])

```
