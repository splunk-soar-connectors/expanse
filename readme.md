[comment]: # "Auto-generated SOAR connector documentation"
# Expanse

Publisher: Expanse  
Connector Version: 1\.1\.3  
Product Vendor: Expanse  
Product Name: Expanse  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

Expanse allows you to perform enrichment using Expanse's Internet Asset data, including IP, Domain, Certificates, and more

[comment]: # " File: readme.md"
[comment]: # ""
[comment]: # "  Copyright (c) Expanse, 2020-2021"
[comment]: # ""
[comment]: # "  Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "  you may not use this file except in compliance with the License."
[comment]: # "  You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "      http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "  Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "  the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "  either express or implied. See the License for the specific language governing permissions"
[comment]: # "  and limitations under the License."
[comment]: # ""
## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Expanse server. Below are the default
ports used by the Splunk SOAR Connector.

| SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Expanse asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**Token** |  required  | password | Token to authenticate API calls
**verify\_server\_cert** |  optional  | boolean | Verify server certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[lookup ip](#action-lookup-ip) - Check for the presence of an IP within a known IP range in Expanse  
[lookup domain](#action-lookup-domain) - Check for the presence of a known domain in Expanse  
[lookup certificate](#action-lookup-certificate) - Returns certificates from Expanse for a full or partial common name  
[lookup behavior](#action-lookup-behavior) - Returns Expanse behavior data for an IP\. Limited to 30 flows within the last 30 days  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup ip'
Check for the presence of an IP within a known IP range in Expanse

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to lookup | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.0\.data\.\*\.annotations\.additionalNotes | string | 
action\_result\.data\.0\.data\.\*\.annotations\.pointsOfContact\.0\.email | string | 
action\_result\.data\.0\.data\.\*\.businessUnits\.0\.name | string | 
action\_result\.data\.0\.data\.\*\.created | string | 
action\_result\.data\.0\.data\.\*\.customChildRanges | string | 
action\_result\.data\.0\.data\.\*\.endAddress | string |  `ip` 
action\_result\.data\.0\.data\.\*\.locationInformation\.0\.geolocation\.countryCode | string | 
action\_result\.data\.0\.data\.\*\.modified | string | 
action\_result\.data\.0\.data\.\*\.responsiveIpCount | numeric | 
action\_result\.data\.0\.data\.\*\.severity\_counts\.CRITICAL | numeric | 
action\_result\.data\.0\.data\.\*\.severity\_counts\.ROUTINE | numeric | 
action\_result\.data\.0\.data\.\*\.severity\_counts\.WARNING | numeric | 
action\_result\.data\.0\.data\.\*\.startAddress | string |  `ip` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup domain'
Check for the presence of a known domain in Expanse

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to lookup | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.data\.0\.data\.\*\.businessUnits\.0\.name | string | 
action\_result\.data\.0\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.0\.data\.\*\.firstObserved | string | 
action\_result\.data\.0\.data\.\*\.lastObserved | string | 
action\_result\.data\.0\.data\.\*\.lastSampledIp | string |  `ip` 
action\_result\.data\.0\.data\.\*\.providers\.0\.name | string | 
action\_result\.data\.0\.data\.\*\.whois\.0\.nameServers | string |  `domain` 
action\_result\.data\.0\.data\.\*\.whois\.0\.registrant\.emailAddress | string |  `email` 
action\_result\.data\.0\.data\.\*\.whois\.0\.registrar\.name | string | 
action\_result\.data\.0\.data\.\*\.whois\.0\.registryExpiryDate | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup certificate'
Returns certificates from Expanse for a full or partial common name

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**common\_name** |  required  | Search for given certificate value via a domain substring match | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.common\_name | string | 
action\_result\.data\.0\.data\.\*\.businessUnits\.0\.name | string | 
action\_result\.data\.0\.data\.\*\.certificate\.issuerName | string | 
action\_result\.data\.0\.data\.\*\.certificate\.md5Hash | string | 
action\_result\.data\.0\.data\.\*\.certificate\.pemSha1 | string | 
action\_result\.data\.0\.data\.\*\.certificate\.pemSha256 | string | 
action\_result\.data\.0\.data\.\*\.certificate\.publicKeyAlgorithm | string | 
action\_result\.data\.0\.data\.\*\.certificate\.publicKeyBits | string | 
action\_result\.data\.0\.data\.\*\.certificate\.subjectName | string | 
action\_result\.data\.0\.data\.\*\.certificate\.validNotAfter | string | 
action\_result\.data\.0\.data\.\*\.certificateAdvertisementStatus\.0 | string | 
action\_result\.data\.0\.data\.\*\.commonName | string |  `domain` 
action\_result\.data\.0\.data\.\*\.firstObserved | string | 
action\_result\.data\.0\.data\.\*\.lastObserved | string | 
action\_result\.data\.0\.data\.\*\.providers\.0\.name | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup behavior'
Returns Expanse behavior data for an IP\. Limited to 30 flows within the last 30 days

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | Internal IP address to search for | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.0\.data\.\*\.externalAddress | string |  `ip` 
action\_result\.data\.0\.data\.\*\.externalCountryCode | string | 
action\_result\.data\.0\.data\.\*\.externalPort | string |  `port` 
action\_result\.data\.0\.data\.\*\.flowDirection | string | 
action\_result\.data\.0\.data\.\*\.internalAddress | string |  `ip` 
action\_result\.data\.0\.data\.\*\.internalCountryCode | string | 
action\_result\.data\.0\.data\.\*\.internalPort | string |  `port` 
action\_result\.data\.0\.data\.\*\.observationTimestamp | string | 
action\_result\.data\.0\.data\.\*\.protocol | string | 
action\_result\.data\.0\.data\.\*\.riskRule\.name | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 