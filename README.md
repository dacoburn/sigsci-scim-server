# SigSci SCIM Server Exampple

Basic SCIM Server based on Okta's Example at https://github.com/oktadeveloper/okta-scim-beta

# Running

It should be as simple as running `python scim-server-sigsci.py`

There are self signed certs that you can use for testing but I recommend creating your own or using real certs...


# Authentication

I have setup the server to use Three headers for authentication. These values are effectively passed on to the SigSci API.

**Headers**
| Name | Value |
|------|-------|
| x-api-user | This is the username to authenticate to Sigsci with i.e. `user@domain.com` |
| x-api-token | API Token of the API User for authentication |
| x-api-corp | API Name for your corp |


# Provisioning 

The Scim server supports the following methods:

| Method | Path | Function |
|--------|------|----------|
| GET    | /scim/v2/Users | Get all users in Signal Sciences. With how the SigSci API works there is one call two get the basic list and then for every user a call to get the site memberships. So if you have 10 users that would be 11 API Calls |
| POST   | /scim/v2/Users | This will create a new user |
| GET    | /scim/v2/Users/<user_id> | This will get the details for that specific user, returns 404 if not created |
| PATCH  | /scim/v2/Users/<user_id> | This will update a user, with the SigSci API only the `role` and `sites` are updatable, everything else cannot be changed |
| PUT    | /scim/v2/Users/<user_id> | Due to the previously mentioned contstraints on updating a user, put will actually **DELETE** the user. There is no way to mark as inactive in SigSci |