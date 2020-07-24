# common-osint-model
**Note:** This is work in progress and probably only covers my specific use case. If you find bugs or know how to
enhance this project, please open an issue or - even better - create a pull request.  
  
This project aims to create an easy to use data model as well as implement converters for commonly used sources. As my
use case often includes HTTP(S), TLS and SSH only, data delivered for other protocols by the given sources might not
show up correctly.

## The data model
Please see the following examples of the data model - given as json but as it's a python dict, you can use other output
formats:

 - [Original Shodan data for 9.9.9.9](test_data/9.9.9.9_shodan.json) and the [flattened common model conversion](test_data/9.9.9.9_shodan_flattened.json)
 - [Original Censys data for 9.9.9.9](test_data/9.9.9.9_censys.json) and the [flattened common model conversion](test_data/9.9.9.9_censys_flattened.json)
 - [Original Shodan data for github.com](test_data/140.82.118.4_shodan.json) and the [flattened common model conversion](test_data/140.82.118.4_shodan_flattened.json) 
 - [Original Censys data for github.com](test_data/140.82.118.4_censys.json) and the [flattened common model conversion](test_data/140.82.118.4_censys_flattened.json)
 - [Certificate for google.com](test_data/www-google-com.pem) and the [flattened common model conversion](test_data/www-google-com_flattened.pem)
 - [Original Censys Certificate for google.com](test_data/www-google-com_censys.json) and the [flattened common model conversion](test_data/www-google-com_censys_flattened.json) 

Currently, only HTTP(S), TLS and SSH data as well as some meta data will get converted. TLS data includes information about other services using TLS, beside HTTPS, too.

## How to use

### Installation
```bash
pip install git+https://github.com/3c7/common-osint-model
```

### Convert all the things
```python
from common_osint_model import from_shodan, from_shodan_flattened, from_censys_ipv4, from_censys_ipv4_flattened, from_x509_pem, from_x509_pem_flattened

raw_shodan = get_my_shodan_data()
converted_s = from_shodan(raw_shodan)
flattened_s = from_shodan_flattened(raw_shodan)

raw_censys_ipv4 = get_my_censys_ipv4_data()
converted_c = from_censys_ipv4(raw_censys_ipv4)
flattened_c = from_censys_ipv4_flattened(raw_censys_ipv4)

raw_certificate = open('certificate.pem').read()
converted_certificate = from_x509_pem(raw_shodan)
flattened_certificate = from_x509_pem_flattened(raw_shodan)
```
