#!/usr/bin/env python3
import contextlib
import os
import random
import re
import signal
import sys

try:
    from z3 import ArithRef, BitVec, BitVecRef, BitVecVal, Solver, simplify, unsat
except Exception:
    print("Missing dependency: please install z3-solver (pip install z3-solver)")
    sys.exit(1)

WIDTH = 32
OPS = ['~', '&', '^', '|']
MAX_DEPTH = 10
FLAG = os.getenv('FLAG', 'flagmx{fake_flag}')
VARS = set('iIl')

def rnd_const() -> tuple[str, BitVecRef]:
    v = random.getrandbits(WIDTH)
    return str(v), BitVecVal(v, WIDTH)


def rnd_var() -> tuple[str, BitVecRef]:
    name = ''.join(random.choices(tuple(VARS), k=10))
    return name, BitVec(name, WIDTH)

def combine(
    op: str,
    left: tuple[str, BitVecRef],
    right: tuple[str, BitVecRef] | None = None,
) -> tuple[str, ArithRef]:
    if op == '~':
        s_left, z_left = left
        return f'(~{s_left})', ~z_left
    s_l, z_l = left
    s_r, z_r = right
    return f'({s_l} {op} {s_r})', {
        '&': z_l & z_r,
        '^': z_l ^ z_r,
        '|': z_l | z_r,
    }[op]

def random_expr(depth: int = 0) -> tuple[str, ArithRef]:
    if depth >= MAX_DEPTH or random.random() < 0.1:
        return random.choice((rnd_var, rnd_const))()
    op = random.choice(OPS)
    if op == '~':
        return combine(op, random_expr(depth + 1))
    return combine(op, random_expr(depth + 1), random_expr(depth + 1))

TOKEN_RE = re.compile(r'[0-9]+|[iIl]+|[~&^|]')

def parse_rpn(s: str) -> ArithRef:
    tokens = TOKEN_RE.findall(s)
    if not tokens:
        raise ValueError('empty input')

    var_cache: dict[str, BitVecRef] = {}
    stack: list[BitVecRef] = []

    for t in tokens:
        if t.isdigit():
            stack.append(BitVecVal(int(t), WIDTH))
        elif re.fullmatch(r'[iIl]+', t):
            if t not in var_cache:
                var_cache[t] = BitVec(t, WIDTH)
            stack.append(var_cache[t])
        elif t in OPS:
            if t == '~':
                if len(stack) < 1:
                    raise ValueError('stack underflow')
                a = stack.pop()
                stack.append(~a)
            else:
                if len(stack) < 2:
                    raise ValueError('stack underflow')
                b = stack.pop()
                a = stack.pop()
                stack.append({'&': a & b, '^': a ^ b, '|': a | b}[t])
        else:
            raise ValueError(f'bad token {t}')

    if len(stack) != 1:
        raise ValueError('malformed expression')
    return stack[0]


def equivalent(e1: ArithRef, e2: ArithRef) -> tuple[bool, Solver]:
    s = Solver()
    s.set(timeout=5000)
    s.add(simplify(e1) != simplify(e2))
    return s.check() == unsat, s


def _timeout_handler(_: int, __) -> None:
    raise TimeoutError


def main() -> None:
    signal.signal(signal.SIGALRM, _timeout_handler)
    print('lets play a game!')

    for _ in range(50):
        random.seed()
        expr_str, expr_z3 = random_expr()
        print(expr_str, flush=True)

        signal.alarm(5)
        try:
            line = sys.stdin.readline()
            signal.alarm(0)
        except TimeoutError:
            print('too slow!')
            return

        try:
            rpn_z3 = parse_rpn(line.strip())
        except Exception as e:
            print('invalid input:', e)
            return

        print('let me see..')
        is_eq, s = equivalent(expr_z3, rpn_z3)
        if not is_eq:
            print('wrong!')
            with contextlib.suppress(BaseException):
                print('counter example:', s.model())
            return

    print(FLAG)

    
if __name__ == '__main__':
    main()
