import grpc
from openshell import SandboxClient
from openshell._proto import openshell_pb2, openshell_pb2_grpc, sandbox_pb2

assert SandboxClient
assert openshell_pb2_grpc.OpenShellStub
assert sandbox_pb2.GetSandboxConfigRequest
assert openshell_pb2.UpdateConfigRequest
channel = grpc.insecure_channel("127.0.0.1:1")
channel.close()
print("openshell SDK imported successfully.")
