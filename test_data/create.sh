#!/usr/bin/env bash

convshodan -F 140.82.118.4_shodan.json > 140.82.118.4_shodan_flattened.json
convshodan -F 9.9.9.9_shodan.json > 9.9.9.9_shodan_flattened.json
convcensys -F 140.82.118.4_censys.json > 140.82.118.4_censys_flattened.json
convcensys -F 9.9.9.9_censys.json > 9.9.9.9_censys_flattened.json
convcert -F www-google-com.pem > www-google-com_flattened.pem
