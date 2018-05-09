# Export these error codes
AUTH_SUCESS = 0
AUTH_UNMATCHED_TRADE = -1
AUTH_INVALID_ARG_ERR = -2
AUTH_INVALID_METHOD_ERR = -3
AUTH_POOL_FULL = -4
AUTH_IN_REG_PERIOD = -5
AUTH_OUTSIDE_REG_PERIOD = -6

def auth_geterror(e):
    return {
        AUTH_SUCESS: "AUTH: Success",
        AUTH_UNMATCHED_TRADE: "AUTH: Unmatched Trade",
        AUTH_INVALID_ARG_ERR: "AUTH: Invalid Argument Error",
        AUTH_INVALID_METHOD_ERR: "AUTH: Invalid Method Error",
        AUTH_POOL_FULL: "AUTH: Dark Pool Is Full. Register During next period",
        AUTH_IN_REG_PERIOD: "AUTH: Attempt failed as registration period is ongoing",
        AUTH_OUTSIDE_REG_PERIOD: "AUTH: Attempt to Register outside reg period"
    }.get(e)
