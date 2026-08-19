// A compact model of the RFC 6749 authorization-code exchange plus the
// RFC 7636 PKCE checks that aioauth implements.
//
// Install Quint and run:
//   quint run formal/oauth_authorization_code_pkce.qnt --invariant=authorizationCodeSafety
//   quint verify formal/oauth_authorization_code_pkce.qnt --invariant=authorizationCodeSafety
//
// For model-based tests:
//   mkdir -p formal/traces
//   quint run formal/oauth_authorization_code_pkce.qnt --mbt --n-traces=100 --out-itf=formal/traces/auth-code.itf.json

module oauth_authorization_code_pkce {
  type RedirectUri = UriA | UriB
  type PkceMode = NoPkce | Plain | S256
  type Error =
    NoError
    | InvalidClient
    | InvalidRequest
    | InvalidGrant
    | InvalidScope
    | UnauthorizedClient

  var codeIssued: bool
  var codeConsumed: bool
  var tokenIssued: bool
  var codeRedirectUri: RedirectUri
  var codeScopeAllowed: bool
  var codeExpired: bool
  var codePkceMode: PkceMode
  var tokenRedirectUri: RedirectUri
  var tokenClientMatches: bool
  var tokenGrantAllowed: bool
  var tokenScopeAllowed: bool
  var tokenCodePresent: bool
  var tokenVerifierPresent: bool
  var tokenVerifierMatches: bool
  var error: Error

  action init = all {
    codeIssued' = false,
    codeConsumed' = false,
    tokenIssued' = false,
    codeRedirectUri' = UriA,
    codeScopeAllowed' = true,
    codeExpired' = false,
    codePkceMode' = NoPkce,
    tokenRedirectUri' = UriA,
    tokenClientMatches' = true,
    tokenGrantAllowed' = true,
    tokenScopeAllowed' = true,
    tokenCodePresent' = true,
    tokenVerifierPresent' = true,
    tokenVerifierMatches' = true,
    error' = NoError,
  }

  action authorize = {
    nondet redirectUri = Set(UriA, UriB).oneOf()
    nondet scopeAllowed = Set(true, false).oneOf()
    nondet pkceMode = Set(NoPkce, Plain, S256).oneOf()
    nondet expired = Set(true, false).oneOf()

    all {
      not(codeIssued),
      codeIssued' = scopeAllowed,
      codeConsumed' = false,
      tokenIssued' = false,
      codeRedirectUri' = redirectUri,
      codeScopeAllowed' = scopeAllowed,
      codeExpired' = expired,
      codePkceMode' = pkceMode,
      tokenRedirectUri' = tokenRedirectUri,
      tokenClientMatches' = tokenClientMatches,
      tokenGrantAllowed' = tokenGrantAllowed,
      tokenScopeAllowed' = tokenScopeAllowed,
      tokenCodePresent' = tokenCodePresent,
      tokenVerifierPresent' = tokenVerifierPresent,
      tokenVerifierMatches' = tokenVerifierMatches,
      error' = if (scopeAllowed) NoError else InvalidScope,
    }
  }

  val pkceSatisfied =
    codePkceMode == NoPkce
    or (tokenVerifierPresent and tokenVerifierMatches)

  def validTokenRequest(
    redirectUri,
    clientMatches,
    grantAllowed,
    scopeAllowed,
    codePresent,
    verifierPresent,
    verifierMatches
  ) =
    codeIssued
    and not(codeConsumed)
    and not(tokenIssued)
    and codePresent
    and clientMatches
    and grantAllowed
    and scopeAllowed
    and not(codeExpired)
    and redirectUri == codeRedirectUri
    and (
      codePkceMode == NoPkce
      or (verifierPresent and verifierMatches)
    )

  action exchangeAuthorizationCode = {
    nondet redirectUri = Set(UriA, UriB).oneOf()
    nondet clientMatches = Set(true, false).oneOf()
    nondet grantAllowed = Set(true, false).oneOf()
    nondet scopeAllowed = Set(true, false).oneOf()
    nondet codePresent = Set(true, false).oneOf()
    nondet verifierPresent = Set(true, false).oneOf()
    nondet verifierMatches = Set(true, false).oneOf()

    all {
      not(tokenIssued),
      tokenRedirectUri' = redirectUri,
      tokenClientMatches' = clientMatches,
      tokenGrantAllowed' = grantAllowed,
      tokenScopeAllowed' = scopeAllowed,
      tokenCodePresent' = codePresent,
      tokenVerifierPresent' = verifierPresent,
      tokenVerifierMatches' = verifierMatches,
      codeIssued' = codeIssued,
      codeRedirectUri' = codeRedirectUri,
      codeScopeAllowed' = codeScopeAllowed,
      codeExpired' = codeExpired,
      codePkceMode' = codePkceMode,
      codeConsumed' = if (validTokenRequest(
        redirectUri,
        clientMatches,
        grantAllowed,
        scopeAllowed,
        codePresent,
        verifierPresent,
        verifierMatches
      )) true else codeConsumed,
      tokenIssued' = if (validTokenRequest(
        redirectUri,
        clientMatches,
        grantAllowed,
        scopeAllowed,
        codePresent,
        verifierPresent,
        verifierMatches
      )) true else tokenIssued,
      error' =
        if (validTokenRequest(
          redirectUri,
          clientMatches,
          grantAllowed,
          scopeAllowed,
          codePresent,
          verifierPresent,
          verifierMatches
        )) NoError
        else if (not(clientMatches)) InvalidClient
        else if (not(grantAllowed)) UnauthorizedClient
        else if (not(scopeAllowed)) InvalidScope
        else if (not(codePresent)) InvalidRequest
        else InvalidGrant,
    }
  }

  action stutter = all {
    codeIssued' = codeIssued,
    codeConsumed' = codeConsumed,
    tokenIssued' = tokenIssued,
    codeRedirectUri' = codeRedirectUri,
    codeScopeAllowed' = codeScopeAllowed,
    codeExpired' = codeExpired,
    codePkceMode' = codePkceMode,
    tokenRedirectUri' = tokenRedirectUri,
    tokenClientMatches' = tokenClientMatches,
    tokenGrantAllowed' = tokenGrantAllowed,
    tokenScopeAllowed' = tokenScopeAllowed,
    tokenCodePresent' = tokenCodePresent,
    tokenVerifierPresent' = tokenVerifierPresent,
    tokenVerifierMatches' = tokenVerifierMatches,
    error' = error,
  }

  action step = any {
    authorize,
    exchangeAuthorizationCode,
    stutter,
  }

  val authorizationCodeSafety = and {
    tokenIssued implies codeIssued,
    tokenIssued implies codeConsumed,
    tokenIssued implies not(codeExpired),
    tokenIssued implies tokenClientMatches,
    tokenIssued implies tokenGrantAllowed,
    tokenIssued implies tokenScopeAllowed,
    tokenIssued implies tokenRedirectUri == codeRedirectUri,
    tokenIssued implies pkceSatisfied,
  }
}
