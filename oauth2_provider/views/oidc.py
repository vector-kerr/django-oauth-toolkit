import json
import logging
from urllib.parse import urlparse

from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from jwcrypto import jwk

from ..models import get_application_model
from ..settings import oauth2_settings
from .mixins import OAuthLibMixin, OIDCOnlyMixin


log = logging.getLogger("oauth2_provider")

Application = get_application_model()


class ConnectDiscoveryInfoView(OIDCOnlyMixin, View):
    """
    View used to show oidc provider configuration information per
    `OpenID Provider Metadata <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>`_
    """

    def get(self, request, *args, **kwargs):
        issuer_url = oauth2_settings.OIDC_ISS_ENDPOINT

        if not issuer_url:
            issuer_url = oauth2_settings.oidc_issuer(request)
            authorization_endpoint = request.build_absolute_uri(reverse("oauth2_provider:authorize"))
            token_endpoint = request.build_absolute_uri(reverse("oauth2_provider:token"))
            userinfo_endpoint = oauth2_settings.OIDC_USERINFO_ENDPOINT or request.build_absolute_uri(
                reverse("oauth2_provider:user-info")
            )
            jwks_uri = request.build_absolute_uri(reverse("oauth2_provider:jwks-info"))
        else:
            parsed_url = urlparse(oauth2_settings.OIDC_ISS_ENDPOINT)
            host = parsed_url.scheme + "://" + parsed_url.netloc
            authorization_endpoint = "{}{}".format(host, reverse("oauth2_provider:authorize"))
            token_endpoint = "{}{}".format(host, reverse("oauth2_provider:token"))
            userinfo_endpoint = oauth2_settings.OIDC_USERINFO_ENDPOINT or "{}{}".format(
                host, reverse("oauth2_provider:user-info")
            )
            jwks_uri = "{}{}".format(host, reverse("oauth2_provider:jwks-info"))

        signing_algorithms = [Application.HS256_ALGORITHM]
        if oauth2_settings.OIDC_RSA_PRIVATE_KEY:
            signing_algorithms = [Application.RS256_ALGORITHM, Application.HS256_ALGORITHM]

        validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
        validator = validator_class()
        oidc_claims = list(set(validator.get_discovery_claims(request)))
        scopes_class = oauth2_settings.SCOPES_BACKEND_CLASS
        scopes = scopes_class()
        scopes_supported = [scope for scope in scopes.get_available_scopes()]

        data = {
            "issuer": issuer_url,
            "authorization_endpoint": authorization_endpoint,
            "token_endpoint": token_endpoint,
            "userinfo_endpoint": userinfo_endpoint,
            "jwks_uri": jwks_uri,
            "scopes_supported": scopes_supported,
            "response_types_supported": oauth2_settings.OIDC_RESPONSE_TYPES_SUPPORTED,
            "subject_types_supported": oauth2_settings.OIDC_SUBJECT_TYPES_SUPPORTED,
            "id_token_signing_alg_values_supported": signing_algorithms,
            "token_endpoint_auth_methods_supported": (
                oauth2_settings.OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED
            ),
            "claims_supported": oidc_claims,
        }
        response = JsonResponse(data)
        response["Access-Control-Allow-Origin"] = "*"
        return response


class JwksInfoView(OIDCOnlyMixin, View):
    """
    View used to show oidc json web key set document
    """

    def get(self, request, *args, **kwargs):
        keys = []
        if oauth2_settings.OIDC_RSA_PRIVATE_KEY:
            for pem in [
                oauth2_settings.OIDC_RSA_PRIVATE_KEY,
                *oauth2_settings.OIDC_RSA_PRIVATE_KEYS_INACTIVE,
            ]:

                key = jwk.JWK.from_pem(pem.encode("utf8"))
                data = {"alg": "RS256", "use": "sig", "kid": key.thumbprint()}
                data.update(json.loads(key.export_public()))
                keys.append(data)
        response = JsonResponse({"keys": keys})
        response["Access-Control-Allow-Origin"] = "*"
        response["Cache-Control"] = (
            "Cache-Control: public, "
            + f"max-age={oauth2_settings.OIDC_JWKS_MAX_AGE_SECONDS}, "
            + f"stale-while-revalidate={oauth2_settings.OIDC_JWKS_MAX_AGE_SECONDS}, "
            + f"stale-if-error={oauth2_settings.OIDC_JWKS_MAX_AGE_SECONDS}"
        )
        return response


@method_decorator(csrf_exempt, name="dispatch")
class UserInfoView(OIDCOnlyMixin, OAuthLibMixin, View):
    """
    View used to show Claims about the authenticated End-User
    """

    def get(self, request, *args, **kwargs):
        return self._create_userinfo_response(request)

    def post(self, request, *args, **kwargs):
        return self._create_userinfo_response(request)

    def _create_userinfo_response(self, request):
        url, headers, body, status = self.create_userinfo_response(request)
        response = HttpResponse(content=body or "", status=status)

        for k, v in headers.items():
            response[k] = v
        return response


class EndSessionView(OIDCOnlyMixin, OAuthLibMixin, View):
    """
    View used to end an OIDC session
    """

    """
    https://openid.net/specs/openid-connect-rpinitiated-1_0.html
    """

    def get(self, request, *args, **kwargs):
        """
        OpenID Providers MUST support the use of the HTTP GET and POST methods defined in RFC 7231
        [RFC7231] at the Logout Endpoint. RPs MAY use the HTTP GET or POST methods to send the
        logout request to the OP.If using the HTTP GET method, the request parameters are serialized
        using URI Query String Serialization.
        """
        return self._end_session(request, request.GET)

    def post(self, request, *args, **kwargs):
        """
        OpenID Providers MUST support the use of the HTTP GET and POST methods defined in RFC 7231
        [RFC7231] at the Logout Endpoint. RPs MAY use the HTTP GET or POST methods to send the
        logout request to the OP. If using the HTTP POST method, the request parameters are
        serialized using Form Serialization.
        """
        return self._end_session(request, request.POST)

    def _end_session(self, request, data):

        id_token_hint = data.get("id_token_hint")
        """
        RECOMMENDED. ID Token previously issued by the OP to the RP passed to the Logout Endpoint
        as a hint about the End-User's current authenticated session with the Client. This is used
        as an indication of the identity of the End-User that the RP is requesting be logged out
        by the OP.
        """

        # logout_hint = data.get("logout_hint")
        """
        OPTIONAL. Hint to the Authorization Server about the End-User that is logging out. The value
        and meaning of this parameter is left up to the OP's discretion. For instance, the value
        might contain an email address, phone number, username, or session identifier pertaining
        to the RP's session with the OP for the End-User. (This parameter is intended to be analogous
        to the login_hint parameter defined in Section 3.1.2.1 of OpenID Connect Core 1.0
        [OpenID.Core] that is used in Authentication Requests; whereas, logout_hint is used in
        RP-Initiated Logout Requests.)
        """

        client_id = data.get("client_id")
        """
        OPTIONAL. OAuth 2.0 Client Identifier valid at the Authorization Server. When both client_id
        and id_token_hint are present, the OP MUST verify that the Client Identifier matches the one
        used when issuing the ID Token. The most common use case for this parameter is to specify the
        Client Identifier when post_logout_redirect_uri is used but id_token_hint is not. Another use
        is for symmetrically encrypted ID Tokens used as id_token_hint values that require the Client
        Identifier to be specified by other means, so that the ID Tokens can be decrypted by the OP.
        """

        # post_logout_redirect_uri = data.get("post_logout_redirect_uri")
        """
        OPTIONAL. URI to which the RP is requesting that the End-User's User Agent be redirected
        after a logout has been performed. This URI SHOULD use the https scheme and MAY contain port,
        path, and query parameter components; however, it MAY use the http scheme, provided that the
        Client Type is confidential, as defined in Section 2.1 of OAuth 2.0 [RFC6749], and provided
        the OP allows the use of http RP URIs. The URI MAY use an alternate scheme, such as one that
        is intended to identify a callback into a native application. The value MUST have been
        previously registered with the OP, either using the post_logout_redirect_uris Registration
        parameter or via another mechanism. An id_token_hint is also RECOMMENDED when this parameter
        is included.
        """

        # state = data.get("state")
        """
        OPTIONAL. Opaque value used by the RP to maintain state between the logout request and the
        callback to the endpoint specified by the post_logout_redirect_uri parameter. If included in
        the logout request, the OP passes this value back to the RP using the state parameter when
        redirecting the User Agent back to the RP.
        """

        # ui_locales = data.get("ui_locales")
        """
        OPTIONAL. End-User's preferred languages and scripts for the user interface, represented as
        a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference. For
        instance, the value "fr-CA fr en" represents a preference for French as spoken in Canada,
        then French (without a region designation), followed by English (without a region
        designation). An error SHOULD NOT result if some or all of the requested locales are not
        supported by the OpenID Provider.
        """

        # If an ID Token Hint is supplied:
        # 1. Verify the JWT ID Token
        # 2. Extract the payload of the JWT ID Token
        # 3. Retrieve the matching ID token (on JTI field) from the database
        #    (If the token cannot be found then ...fail?...)
        id_token = None
        if id_token_hint is not None:
            id_token = self.get_validator_class()._load_id_token(id_token_hint)
            assert id_token is not None

        # If a Client ID is supplied:
        application = None
        if client_id is not None:
            application = Application.objects.get(client_id=client_id)
            if not application.is_usable(request):
                log.debug("Failed body authentication: Application %r is disabled" % (client_id))
                return None

        """
        When both client_id and id_token_hint are present, the OP MUST verify that the Client
        Identifier matches the one used when issuing the ID Token.
        """
        if id_token_hint is not None and client_id is not None:
            assert id_token is not None
            assert application is not None
            assert id_token.application == application

        """
        When an id_token_hint parameter is present, the OP MUST validate that it was the issuer of
        the ID Token. The OP SHOULD accept ID Tokens when the RP identified by the ID Token's aud
        claim and/or sid claim has a current session or had a recent session at the OP, even when
        the exp time has passed. If the ID Token's sid claim does not correspond to the RP's current
        session or a recent session at the OP, the OP SHOULD treat the logout request as suspect,
        and MAY decline to act upon it.
        """
        if id_token_hint is not None:
            expected_issuer = self.get_validator_class.get_oidc_issuer_endpoint(request)
            actual_issuer = self.get_validator_class._get_issuer_for_token(id_token_hint)
            assert id_token is not None
            assert actual_issuer == expected_issuer

            raise NotImplementedError(
                "The OP SHOULD accept ID Tokens when the RP identified by" " the ID Token's aud claim"
            )

        """
        At the Logout Endpoint, the OP SHOULD ask the End-User whether to log out of the OP as well.
        Furthermore, the OP MUST ask the End-User this question if an id_token_hint was not provided
        or if the supplied ID Token does not belong to the current OP session with the RP and/or
        currently logged in End-User. If the End-User says "yes", then the OP MUST log out the End-User.
        """
        # TODO
        id_token_belongs_to_current_session = False
        if id_token_hint is None or not id_token_belongs_to_current_session:
            raise NotImplementedError()

        """
        As part of the OP logging out the End-User, the OP uses the logout mechanism(s) registered
        by the RPs to notify any RPs logged in as that End-User that they are to likewise log out
        the End-User. RPs can use any of OpenID Connect Session Management 1.0 [OpenID.Session],
        OpenID Connect Front-Channel Logout 1.0 [OpenID.FrontChannel], and/or OpenID Connect
        Back-Channel Logout 1.0 [OpenID.BackChannel] to receive logout notifications from the OP,
        depending upon which of these mechanisms the OP and RPs mutually support. The RP initiating
        the logout is to be included in these notifications before the post-logout redirection defined
        in Section 3 is performed.

        It is up to the RP whether to locally log out the End-User before redirecting the User Agent
        to the OP's Logout Endpoint. On one hand, if the End-User approves the logout at the OP, the
        RP initiating the logout should receive a logout message from the OP and can perform a local
        logout at that time. On the other hand, some logout notification methods from the OP to the RP
        are unreliable and therefore the notification might not be received. Also, the End-User might
        not approve the OP logging out, in which case the RP would not receive a logout notification.
        """
        # TODO:Send front/back/session logout notifications
        raise NotImplementedError()

        """
        In some cases, the RP will request that the End-User's User Agent to be redirected back to
        the RP after a logout has been performed. Post-logout redirection is only done when the
        logout is RP-initiated, in which case the redirection target is the post_logout_redirect_uri
        parameter value sent by the initiating RP. An id_token_hint carring an ID Token for the RP
        is also RECOMMENDED when requesting post-logout redirection; if it is not supplied with
        post_logout_redirect_uri, the OP MUST NOT perform post-logout redirection unless the OP has
        other means of confirming the legitimacy of the post-logout redirection target. The OP also
        MUST NOT perform post-logout redirection if the post_logout_redirect_uri value supplied does
        not exactly match one of the previously registered post_logout_redirect_uris values. The
        post-logout redirection is performed after the OP has finished notifying the RPs that logged
        in with the OP for that End-User that they are to log out the End-User.
        """
        if id_token_hint is None:
            # Do NOT perform post-logout redirection
            raise NotImplementedError()

        else:
            # Perform post-logout redirection
            raise NotImplementedError()
