import websockets
from websockets.sync.client import connect

with connect("wss://ws.postman-echo.com/raw") as connection:
    test = connection.send("Hello World!")
    echo = connection.recv()
    print(echo)
    connection.close()
    
print("All is good. websockets imported successfully and run against echo server")