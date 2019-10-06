import { Engine } from '@frogfish/engine';

let logger;

export default class AuthHandler {
  constructor(private engine: Engine, private user) {
    logger = engine.log.log('service:auth');
  }

  get(req, res, next) {
    const token = req.header('authorization');

    if (!token) {
      return res.status(401).json({
        error: 'invalid_request',
        error_description: 'Missing bearer token'
      });
    }

    const api = this.engine.auth;

    api
      .resolve(token)
      .then(data => {
        if (!data) {
          return res.status(401).json({
            error: 'invalid_request',
            error_description: 'Token could not be resolved'
          });
        }

        res.json(data);
      })
      .catch(err => {
        err.send(res);
      });
  }

  post(req, res, next) {
    const params = req.body;
    const api = this.engine.auth;
    const token = req.header('authorization');
    const context = req.path.split('/')[3];

    if (token) {
      params.token = token.split(' ')[1];
    }

    logger.debug(`Authorising with context ${context} and params ${JSON.stringify(params, null, 2)}`);

    api
      .authenticate(params, context)
      .then(data => {
        return res.json(data);
      })
      .catch(err => {
        console.log(err);
        return err.send(res);
      });
  }
}

/*
 Access Token Response

 If the access token request is valid and authorized, the
 authorization server issues an access token and optional refresh
 token as described in Section 5.1.  If the request failed client
 authentication or is invalid, the authorization server returns an
 error response as described in Section 5.2.

 An example successful response:

 HTTP/1.1 200 OK
 Content-Type: application/json;charset=UTF-8
 Cache-Control: no-store
 Pragma: no-cache

 {
 "access_token":"2YotnFZFEjr1zCsicMWpAA",
 "token_type":"example",
 "expires_in":3600,
 "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
 "example_parameter":"example_value"
 }
 */

/*

 PASSWORD GRANT TYPE

 The client makes a request to the token endpoint by adding the
 following parameters using the "application/x-www-form-urlencoded"
 format per Appendix B with a character encoding of UTF-8 in the HTTP
 request entity-body:

 grant_type
 REQUIRED.  Value MUST be set to "password".

 username
 REQUIRED.  The resource owner username.

 password
 REQUIRED.  The resource owner password.

 scope
 OPTIONAL.  The scope of the access request as described by
 Section 3.3.

 If the client type is confidential or the client was issued client
 credentials (or assigned other authentication requirements), the
 client MUST authenticate with the authorization server as described
 in Section 3.2.1.

 For example, the client makes the following HTTP request using
 transport-layer security (with extra line breaks for display purposes
 only):

 POST /token HTTP/1.1
 Host: server.example.com
 Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 Content-Type: application/x-www-form-urlencoded

 grant_type=password&username=johndoe&password=A3ddj3w

 The authorization server MUST:

 o  require client authentication for confidential clients or for any
 client that was issued client credentials (or with other
 authentication requirements),

 o  authenticate the client if client authentication is included, and

 o  validate the resource owner password credentials using its
 existing password validation algorithm.

 Since this access token request utilizes the resource owner's
 password, the authorization server MUST protect the endpoint against
 brute force attacks (e.g., using rate-limitation or generating
 */

// interface OauthError {
//     error: string,
//     error_description?: string,
//     error_uri?: string
// }
/*
 error
 REQUIRED.  A single ASCII [USASCII] error code from the
 following:

 invalid_request
 The request is missing a required parameter, includes an
 unsupported parameter value (other than grant type),
 repeats a parameter, includes multiple credentials,
 utilizes more than one mechanism for authenticating the
 client, or is otherwise malformed.

 invalid_client
 Client authentication failed (e.g., unknown client, no
 client authentication included, or unsupported
 authentication method).  The authorization server MAY
 return an HTTP 401 (Unauthorized) status code to indicate
 which HTTP authentication schemes are supported.  If the
 client attempted to authenticate via the "Authorization"
 request header field, the authorization server MUST
 respond with an HTTP 401 (Unauthorized) status code and
 include the "WWW-Authenticate" response header field
 matching the authentication scheme used by the client.

 invalid_grant
 The provided authorization grant (e.g., authorization
 code, resource owner credentials) or refresh token is
 invalid, expired, revoked, does not match the redirection
 URI used in the authorization request, or was issued to
 another client.

 unauthorized_client
 The authenticated client is not authorized to use this
 authorization grant type.

 unsupported_grant_type
 The authorization grant type is not supported by the
 authorization server.

 invalid_scope
 The requested scope is invalid, unknown, malformed, or
 exceeds the scope granted by the resource owner.

 Values for the "error" parameter MUST NOT include characters
 outside the set %x20-21 / %x23-5B / %x5D-7E.

 error_description
 OPTIONAL.  Human-readable ASCII [USASCII] text providing
 additional information, used to assist the client developer in
 understanding the error that occurred.
 Values for the "error_description" parameter MUST NOT include
 characters outside the set %x20-21 / %x23-5B / %x5D-7E.

 error_uri
 OPTIONAL.  A URI identifying a human-readable web page with
 information about the error, used to provide the client
 developer with additional information about the error.
 Values for the "error_uri" parameter MUST conform to the
 URI-reference syntax and thus MUST NOT include characters
 outside the set %x21 / %x23-5B / %x5D-7E.

 The parameters are included in the entity-body of the HTTP response
 using the "application/json" media type as defined by [RFC4627].  The
 parameters are serialized into a JSON structure by adding each
 parameter at the highest structure level.  Parameter names and string
 values are included as JSON strings.  Numerical values are included
 as JSON numbers.  The order of parameters does not matter and can
 vary.

 For example:

 HTTP/1.1 400 Bad Request
 Content-Type: application/json;charset=UTF-8
 Cache-Control: no-store
 Pragma: no-cache

 {
 "error":"invalid_request"
 }
 */
