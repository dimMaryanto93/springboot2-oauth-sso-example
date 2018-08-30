# Springboot security Oauth2 - Enabled sso

## Fitur

- Flow grant type authorization code

    - request code: 

        ```bash
        http://localhost:10000/oauth/authorize?grant_type=authorization_code&client_id=client-code&client_secret=123456&response_type=code&redirectUrl=http://localhost:10000
        ```
    - request access token:
    
        ```bash
        curl -X POST \
          http://localhost:10000/oauth/token \
          -H 'Authorization: Basic Y2xpZW50LWNvZGU6MTIzNDU2' \
          -H 'Cache-Control: no-cache' \
          -H 'Content-Type: application/x-www-form-urlencoded' \
          -d 'grant_type=authorization_code&code=BlTYTC'    
        ```

- Flow grant type password

    ```curl
    curl -X POST \
      http://localhost:10000/oauth/token \
      -H 'Authorization: Basic Y2xpZW50LWNvZGU6MTIzNDU2' \
      -H 'Cache-Control: no-cache' \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -d 'grant_type=password&client_id=client-code&username=user&password=password'
    ```