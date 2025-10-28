import socket

def main():
    s = socket.socket()
    s.connect(('localhost', 5231))
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
            cnt = input()
            s.sendall(cnt.encode())
            for _ in range(int(cnt)):
                print(s.recv(4096).decode(), end='')
                amt = input()
                s.sendall(amt.encode())
        elif choice == '2':
            print(s.recv(8192).decode())
        elif choice == '3':
            break

main()
