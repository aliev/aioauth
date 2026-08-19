// RFC 6749 section 6 refresh-token model.
//
// The key properties:
// - a refresh token can be exchanged only if it exists, belongs to the client,
//   is not expired, and has not been revoked
// - successful rotation revokes the old refresh token
// - a requested scope must not include scopes that were not originally granted
// - omitting scope preserves the old scope

module refresh_token_rotation {
  type ScopeRequest = Omitted | SameScope | SubsetScope | ExtraScope
  type NewScope = NoToken | OldScope | RequestedSubset
  type Error =
    NoError
    | InvalidClient
    | InvalidRequest
    | InvalidGrant
    | InvalidScope
    | UnauthorizedClient

  var oldTokenExists: bool
  var oldTokenRevokedBefore: bool
  var oldTokenExpired: bool
  var oldTokenRevokedAfter: bool
  var clientMatches: bool
  var grantAllowed: bool
  var refreshTokenPresent: bool
  var scopeRequest: ScopeRequest
  var tokenIssued: bool
  var newScope: NewScope
  var error: Error

  action init = all {
    oldTokenExists' = true,
    oldTokenRevokedBefore' = false,
    oldTokenExpired' = false,
    oldTokenRevokedAfter' = false,
    clientMatches' = true,
    grantAllowed' = true,
    refreshTokenPresent' = true,
    scopeRequest' = Omitted,
    tokenIssued' = false,
    newScope' = NoToken,
    error' = NoError,
  }

  def requestedScopeAllowed(scope) =
    scope == Omitted or scope == SameScope or scope == SubsetScope

  def validRefreshRequest(
    tokenExists,
    revokedBefore,
    expired,
    clientOk,
    grantOk,
    tokenPresent,
    scope
  ) =
    tokenExists
    and not(revokedBefore)
    and not(oldTokenRevokedAfter)
    and not(expired)
    and clientOk
    and grantOk
    and tokenPresent
    and requestedScopeAllowed(scope)

  def scopeFor(scope) =
    if (scope == SubsetScope) RequestedSubset else OldScope

  action exchangeRefreshToken = {
    nondet tokenExists = Set(true, false).oneOf()
    nondet revokedBefore = Set(true, false).oneOf()
    nondet expired = Set(true, false).oneOf()
    nondet clientOk = Set(true, false).oneOf()
    nondet grantOk = Set(true, false).oneOf()
    nondet tokenPresent = Set(true, false).oneOf()
    nondet scope = Set(Omitted, SameScope, SubsetScope, ExtraScope).oneOf()

    all {
      not(tokenIssued),
      oldTokenExists' = tokenExists,
      oldTokenRevokedBefore' = revokedBefore,
      oldTokenExpired' = expired,
      clientMatches' = clientOk,
      grantAllowed' = grantOk,
      refreshTokenPresent' = tokenPresent,
      scopeRequest' = scope,
      oldTokenRevokedAfter' = if (validRefreshRequest(
        tokenExists,
        revokedBefore,
        expired,
        clientOk,
        grantOk,
        tokenPresent,
        scope
      )) true else oldTokenRevokedAfter,
      tokenIssued' = validRefreshRequest(
        tokenExists,
        revokedBefore,
        expired,
        clientOk,
        grantOk,
        tokenPresent,
        scope
      ),
      newScope' = if (validRefreshRequest(
        tokenExists,
        revokedBefore,
        expired,
        clientOk,
        grantOk,
        tokenPresent,
        scope
      )) scopeFor(scope) else NoToken,
      error' =
        if (validRefreshRequest(
          tokenExists,
          revokedBefore,
          expired,
          clientOk,
          grantOk,
          tokenPresent,
          scope
        )) NoError
        else if (not(clientOk)) InvalidClient
        else if (not(grantOk)) UnauthorizedClient
        else if (not(tokenPresent)) InvalidRequest
        else if (not(requestedScopeAllowed(scope))) InvalidScope
        else InvalidGrant,
    }
  }

  action stutter = all {
    oldTokenExists' = oldTokenExists,
    oldTokenRevokedBefore' = oldTokenRevokedBefore,
    oldTokenExpired' = oldTokenExpired,
    oldTokenRevokedAfter' = oldTokenRevokedAfter,
    clientMatches' = clientMatches,
    grantAllowed' = grantAllowed,
    refreshTokenPresent' = refreshTokenPresent,
    scopeRequest' = scopeRequest,
    tokenIssued' = tokenIssued,
    newScope' = newScope,
    error' = error,
  }

  action step = any {
    exchangeRefreshToken,
    stutter,
  }

  val refreshTokenSafety = and {
    tokenIssued implies oldTokenExists,
    tokenIssued implies not(oldTokenRevokedBefore),
    tokenIssued implies oldTokenRevokedAfter,
    tokenIssued implies not(oldTokenExpired),
    tokenIssued implies clientMatches,
    tokenIssued implies grantAllowed,
    tokenIssued implies refreshTokenPresent,
    tokenIssued implies requestedScopeAllowed(scopeRequest),
    tokenIssued and scopeRequest == Omitted implies newScope == OldScope,
    tokenIssued and scopeRequest == SameScope implies newScope == OldScope,
    tokenIssued and scopeRequest == SubsetScope implies newScope == RequestedSubset,
  }
}
