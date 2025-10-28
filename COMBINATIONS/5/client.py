import socket

def main():
    s = socket.socket()
    s.connect(('localhost', 5041))
    while True:
        menu = s.recv(4096).decode()
        print(menu, end='')
        choice = input()
        s.sendall(choice.encode())
        if choice == '1':
            print(s.recv(4096).decode(), end='')
            name = input()
            s.sendall(name.encode())
            print(s.recv(4096).decode(), end='')
            n = input()
            s.sendall(n.encode())
            for _ in range(int(n)):
                print(s.recv(4096).decode(), end='')
                amt = input()
                s.sendall(amt.encode())
        elif choice == '2':
            print(s.recv(4096).decode())
        elif choice == '3':
            break

main()
