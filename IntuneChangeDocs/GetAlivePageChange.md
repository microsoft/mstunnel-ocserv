# Get Alive Page changes

Changes in GET response which changes the returned message for the GET alive page
Respons should be "I am still alive!!" : "Please enter your username."

Commit 23c95c71: Changed GET response page

When checking if server is alive or not, this code will output the following response page:
<message>I am still alive !!</message>

Original PR [here](https://msazure.visualstudio.com/One/_git/Intune-Svc-MobileAccess/commit/23c95c71a2d716e35da1fb29f088649be3bef3d8?refName=refs/heads/develop)

## PAM authentication regression fix

Commit b39eb34d decouples the GET health response from authentication-form
generation. When PAM token authentication is enabled with
`pam[use-token=yes]`, the PAM authentication type includes the
username/password flag. The shared response handler therefore appended username
and password input elements after the health message, producing invalid XML:

```xml
<message>I am still alive!!</message>
<input type="text" name="username" label="Username:" />
<input type="password" name="password" label="Password:" />
```

An unknown, non-VPN user agent requesting `GET /` now receives only the stable
health response:

```xml
<message>I am still alive!!</message>
```

This response is independent of whether OIDC or PAM token authentication is
configured. Authentication-form generation for recognized VPN clients and
other request paths is unchanged. The PAM integration test verifies the exact
health response.