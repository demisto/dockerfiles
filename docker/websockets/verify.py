import websockets
from websockets.sync.client import connect


# write a script to test that websockets work properly
with connect("ws://echo.websocket.org") as connection:
    echo = connection.recv()
    print(echo)
    connection.close()
    
print("All is good. websockets imported successfully and run against echo server")