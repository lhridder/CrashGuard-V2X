#!/usr/bin/env python3
from ev3dev2.display import Display
from ev3dev2.sound import Sound
import ev3dev2.fonts as fonts
import socket
import time

HOST = "192.168.1.31"
PORT = 5001
DEVICE_NAME = "EV3-1"

# display
screen = Display()
screen.clear()
screen.update()
_font = fonts.load('helvB24')

# sound
spkr = Sound()

while True:
    try:
        print("setting up connection...")
        screen.clear()
        screen.draw.text((10, 10), 'Connecting...', font=_font)
        screen.update()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        sock.sendall(DEVICE_NAME.encode("utf-8"))
        sock.close()

        print("Sent device name:", DEVICE_NAME)
        screen.clear()
        screen.draw.text((10, 10), 'Connected', font=_font)
        spkr.speak(text="EV3 connected", volume=100)
        screen.update()

    except Exception as e:
        print("Error:", e)
    time.sleep(5)
