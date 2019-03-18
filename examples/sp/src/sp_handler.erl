%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(sp_handler).
-include_lib("esaml/include/esaml.hrl").

-record(state, {sp, idp}).
-export([init/3, handle/2, terminate/3]).

init(_Transport, Req, _Args) ->
    % Load the certificate and private key for the SP
    % PrivKey = esaml_util:load_private_key("test.key"),
    Cert = esaml_util:load_certificate("test.crt"),
    % We build all of our URLs (in metadata, and in requests) based on this
    Base = "http://localhost:8080/saml",
    % Certificate fingerprints to accept from our IDP
    FPs = ["6C:21:74:E7:EA:9F:07:15:4C:5F:8F:4D:26:00:FC:5F:A9:F3:23:E0:85:44:D8:42:74:D5:2D:E3:63:F5:D1:63",
           "BC:52:94:15:1D:34:1F:E7:13:69:98:5F:C7:C0:D1:5F:D8:62:6E:46:59:F2:F7:78:FA:C5:09:BC:49:14:2D:32"],

    SP = esaml_sp:setup(#esaml_sp{
        % key = "PrivKey",
        certificate = Cert,
        trusted_fingerprints = FPs,
        consume_uri = Base ++ "/consume",
        metadata_uri = Base ++ "/metadata",
        org = #esaml_org{
            name = "Foo Bar",
            displayname = "Foo Bar",
            url = "localhost:8080/saml"
        },
        tech = #esaml_contact{
            name = "Foo Bar",
            email = "foo@bar.com"
        }
    }),
    % Rather than copying the IDP's metadata into our code, we'll just fetch it
    % (this call will cache after the first time around, so it will be fast)
    IdpMeta = esaml_util:load_metadata("https://dev-791960.oktapreview.com/app/exkc067ll78MQJ7ws0h7/sso/saml/metadata"),
    % IdpMeta = esaml_util:load_metadata("https://app.onelogin.com/saml/metadata/705309"),

    {ok, Req, #state{sp = SP, idp = IdpMeta}}.

handle(Req, S = #state{}) ->
    {Operation, Req2} = cowboy_req:binding(operation, Req),
    {Method, Req3} = cowboy_req:method(Req2),
    handle(Method, Operation, Req3, S).

% Return our SP metadata as signed XML
handle(<<"GET">>, <<"metadata">>, Req, S = #state{sp = SP}) ->
    {ok, Req2} = esaml_cowboy:reply_with_metadata(SP, Req),
    {ok, Req2, S};

% Visit /saml/auth to start the authentication process -- we will make an AuthnRequest
% and send it to our IDP
handle(<<"GET">>, <<"auth">>, Req, S = #state{sp = SP,
        idp = #esaml_idp_metadata{login_location = IDP}}) ->
    SignedXml = SP:generate_authn_request(IDP),
    Target = esaml_binding:encode_http_redirect(IDP, SignedXml, <<"">>),
    % io:fwrite("\nUsed IDP: ~s\nTarget ~s.", [IDP, Target]),
    {ok, Req2} = cowboy_req:reply(302, [
            {<<"Cache-Control">>, <<"no-cache">>},
            {<<"Pragma">>, <<"no-cache">>},
            {<<"Location">>, Target}
        ], <<"Redirecting...">>, Req),
    {ok, Req2, S};

% Handles HTTP-POST bound assertions coming back from the IDP.
handle(<<"POST">>, <<"consume">>, Req, S = #state{sp = SP}) ->
    case esaml_cowboy:validate_assertion(SP, fun esaml_util:check_dupe_ets/2, Req) of
        {ok, Assertion, RelayState, Req2} ->
            Attrs = Assertion#esaml_assertion.attributes,
            Uid = proplists:get_value(uid, Attrs),
            Output = io_lib:format("<html><head><title>SAML SP demo</title></head><body><h1>Hi there!</h1><p>This is the <code>esaml_sp_default</code> demo SP callback module from eSAML.</p><table><tr><td>Your name:</td><td>\n~p\n</td></tr><tr><td>Your UID:</td><td>\n~p\n</td></tr></table><hr /><p>RelayState:</p><pre>\n~p\n</pre><p>The assertion I got was:</p><pre>\n~p\n</pre></body></html>", [Assertion#esaml_assertion.subject#esaml_subject.name, Uid, RelayState, Assertion]),
            {ok, Req3} = cowboy_req:reply(200, [{<<"Content-Type">>, <<"text/html">>}], Output, Req2),
            {ok, Req3, S};

        {error, Reason, Req2} ->
            {ok, Req3} = cowboy_req:reply(403, [{<<"content-type">>, <<"text/plain">>}],
                ["Access denied, assertion failed validation:\n", io_lib:format("~p\n", [Reason])],
                Req2),
            {ok, Req3, S}
    end;

handle(_, _, Req, S = #state{}) ->
    {ok, Req2} = cowboy_req:reply(404, [], <<"Not found">>, Req),
    {ok, Req2, S}.

terminate(_Reason, _Req, _State) -> ok.
