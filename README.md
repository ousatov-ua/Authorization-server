# Authorization server
This is just an example for authorization server that provides api to get access key (JWT)


## Authorization
Currenlty, it is for client based authorization.

Client can have roles.

Client make request to get access token (JWT)

## Users

Currently, you need to put users into `users.json`.

Please pay attention that you have to use `PasswordUtils` to encode password for the user.

## RSA public and private keys

Please use next commands to generate them:

```shell
openssl genrsa -out rsa.private.key 4096
```

```shell
openssl rsa -in rsa.private.key -out rsa.public.key -pubout -outform PEM
```

Current RSA are commited to repo, so *THEY SHOULD NOT BE USED ON PROD*, please generate new ones.
