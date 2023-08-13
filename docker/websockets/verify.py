import websockets
from websockets.sync.client import connect

with connect("https://www.websocket.org/echo.html") as connection:
    echo = connection.recv()
    print(echo)
    connection.close()
    
print("All is good. websockets imported successfully and run against echo server")