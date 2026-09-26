#!/usr/bin/env python3
import socket
import re

HOST = '45.170.252.24'
PORT = 4443

OPS = ['~', '&', '^', '|']

# convierte infijo a tokens
def tokenize(expr):
    tokens = re.findall(r'[iIl]+|\d+|[~&^|()]', expr)
    return tokens

# Precedencia de operadores
PREC = {'~':3, '&':2, '^':1, '|':0}

# Shunting-yard para convertir a RPN
def infix_to_rpn(tokens):
    out = []
    stack = []
    for tok in tokens:
        if re.fullmatch(r'\d+|[iIl]+', tok):
            out.append(tok)
        elif tok in OPS:
            while stack and stack[-1] in OPS:
                if tok == '~':
                    break
                if PREC[tok] <= PREC[stack[-1]]:
                    out.append(stack.pop())
                else:
                    break
            stack.append(tok)
        elif tok == '(':
            stack.append(tok)
        elif tok == ')':
            while stack and stack[-1] != '(':
                out.append(stack.pop())
            stack.pop()  # eliminar '('
    while stack:
        out.append(stack.pop())
    return out

# interactuar con servidor
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    s_file = s.makefile('rw', buffering=1)

    while True:
        line = s_file.readline()
        if not line:
            print("NO hay mas nada que leer")
            break
        print(line, end='')  # imprimir mensaje del servidor
        if line.strip().startswith('('):  # detecta línea con expresión
            tokens = tokenize(line.strip())
            rpn = infix_to_rpn(tokens)
            rpn_str = ' '.join(rpn)
            print("Sending RPN:", rpn_str)
            s_file.write(rpn_str + '\n')

    s.close()

if __name__ == "__main__":
    main()
