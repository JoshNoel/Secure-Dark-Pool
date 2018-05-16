# Export these error codes
AUTH_SUCCESS = 0
AUTH_UNMATCHED_TRADE = -1
AUTH_INVALID_ARG_ERR = -2
AUTH_INVALID_METHOD_ERR = -3
AUTH_POOL_FULL = -4
AUTH_IN_REG_PERIOD = -5
AUTH_OUTSIDE_REG_PERIOD = -6
AUTH_QUERY_TIMEOUT = -7
AUTH_PERMISSION_ERR = -8
AUTH_MISTYPED_MSG = -9


AUTH_ERRORS = {
    AUTH_SUCCESS: "AUTH: Success",
    AUTH_UNMATCHED_TRADE: "AUTH: Unmatched Trade",
    AUTH_INVALID_ARG_ERR: "AUTH: Invalid Argument Error",
    AUTH_INVALID_METHOD_ERR: "AUTH: Invalid Method Error",
    AUTH_POOL_FULL: "AUTH: Dark Pool Is Full. Register During next period",
    AUTH_IN_REG_PERIOD: "AUTH: Attempt failed as registration period is ongoing",
    AUTH_OUTSIDE_REG_PERIOD: "AUTH: Attempt to Register outside reg period",
    AUTH_QUERY_TIMEOUT: "AUTH: Server query timeout",
    AUTH_PERMISSION_ERR: "AUTH: Permission Denied",
    AUTH_MISTYPED_MSG: "AUTH: Client Handler runtime error. Received message from other client in wrong order"
}
def auth_geterror(e):
    return AUTH_ERRORS[e]

VOLUME_NUM_BITS = 20
MAX_TRADE_VOL = 2**VOLUME_NUM_BITS # 2^20 as we use at most 20 bits for volume calculation

def auth_getvolumebits(volume):
    bit_str = '{0:0{size}b}'.format(abs(volume), size=VOLUME_NUM_BITS)
    return [int(bit_chr) for bit_chr in bit_str]


