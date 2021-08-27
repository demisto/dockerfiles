import os


weights_path = os.path.join("/yolo-coco", "yolov3.weights")

if os.path.exists(weights_path):
    print(f"All is good. Weights path: {weights_path} exists")
