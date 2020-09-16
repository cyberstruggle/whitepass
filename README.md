<center>
<h1>Whitepass</h1>
</center>
Bypass Whitelist/Ratelimit Implementations in Web Applications/APIs

### Main Features
- Parsing Requests from burp-suite
- Customize the request
- Add Additional Headers
- Add Additional Payloads
- Add Known IPs Address for the target
  
### How it's work
Whitepass will try to fuzz the target with additional HTTP-Headers,
Unlike other tools which using X-Originating-IP or X-Forwarded-For.
Whitepass using +70 Different HTTP-Header with tons of payloads trying to bypass different implementations of Whitelist/Ratelimit solutions and functions based on known methods and techniques that developers and webservers using to implement Whitelist/Ratelimit solutions. 
this project was part of DeltaGroup Internal Tools which used in our engagements 

### Using
```bash
#python3.6+ required
python3 whitepass.py -r burp_saved_request
#Test HTTP-Post
python3 whitepass.py -u https://api.company.com/v1/api/login -m post --data "username=test&password=test"
#Simple HTTP-GET
python3 whitepass.py -u https://api.company.com/v1/api/login
#List of endpoints
python3 whitepass.py -l list.txt
#For more using
python3 whitepass.py --help
```

## Credits
* SQLMap [code](https://github.com/sqlmapproject/sqlmap)
* wazehell [author](https://twitter.com/safe_buffer)



