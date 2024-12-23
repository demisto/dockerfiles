FROM alpine:3.17.10 as files-src
COPY weights /yolo-coco

FROM demisto/opencv:1.0.0.114711

COPY requirements.txt .
COPY yolo-coco /yolo-coco/.
COPY --from=files-src /yolo-coco/yolov3.weights /yolo-coco/.

FROM demisto/python3:3.11.10.115186
