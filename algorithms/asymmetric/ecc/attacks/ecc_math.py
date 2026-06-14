"""ECC 小曲线分析辅助函数。"""

from math import isqrt


def parse_int(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return int(text, 0)


def mod_inverse(a, n):
    a %= n
    if a == 0:
        return None
    t, new_t = 0, 1
    r, new_r = n, a
    while new_r:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        return None
    return t % n


def is_on_curve(point, a, b, p):
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + a * x + b)) % p == 0


def point_neg(point, p):
    if point is None:
        return None
    x, y = point
    return (x % p, (-y) % p)


def point_add(p1, p2, a, p):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if p1 == p2:
        numerator = (3 * x1 * x1 + a) % p
        denominator = mod_inverse(2 * y1, p)
    else:
        numerator = (y2 - y1) % p
        denominator = mod_inverse((x2 - x1) % p, p)
    if denominator is None:
        return None
    slope = (numerator * denominator) % p
    x3 = (slope * slope - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return (x3, y3)


def scalar_mul(k, point, a, p):
    if k == 0 or point is None:
        return None
    if k < 0:
        return scalar_mul(-k, point_neg(point, p), a, p)
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend, a, p)
        addend = point_add(addend, addend, a, p)
        k >>= 1
    return result


def point_order(point, a, p, max_steps=None):
    current = point
    limit = max_steps or (p + 1 + 2 * isqrt(p) + 16)
    for order in range(1, limit + 1):
        if current is None:
            return order
        current = point_add(current, point, a, p)
    return None


def discrete_log_bsgs(base_point, target_point, a, p, order_bound):
    if order_bound <= 0:
        return None
    m = isqrt(order_bound) + 1
    baby_steps = {}
    current = None
    for j in range(m):
        if current not in baby_steps:
            baby_steps[current] = j
        current = point_add(current, base_point, a, p)

    factor = scalar_mul(-m, base_point, a, p)
    gamma = target_point
    for i in range(m + 1):
        j = baby_steps.get(gamma)
        if j is not None:
            candidate = i * m + j
            if candidate <= order_bound:
                return candidate
        gamma = point_add(gamma, factor, a, p)
    return None
