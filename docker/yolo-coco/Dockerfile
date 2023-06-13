FROM alpine:3.17.3 as files-src
COPY weights /yolo-coco
RUN cd yolo-coco \
  && cat yolov3.weights.aa yolov3.weights.ab yolov3.weights.ac yolov3.weights.ad yolov3.weights.ae > yolov3.weights

FROM demisto/opencv:1.0.0.49449

COPY requirements.txt .
COPY yolo-coco /yolo-coco/.
COPY --from=files-src /yolo-coco/yolov3.weights /yolo-coco/.

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*
