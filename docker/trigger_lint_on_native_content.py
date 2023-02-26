import argparse
import logging
import time
import sys
import requests
import json

# NATIVE_IMAGE_NAME = "py3-native"
NATIVE_IMAGE_NAME = "testimage"
CIRCLE_ADDRESS = ""
API_PROJECT_URL = ""
PIPELINE_URL_PREFIX = ""

GET_PIPELINES_MAX_RETRIES = 5


parser = argparse.ArgumentParser("Trigger lint on native supported content in content repo.")
parser.add_argument('-ti', '--target-image', help='The image to run lint with', required=True)
parser.add_argument('-ct', '--circle-token', help='The token to trigger circle pipelines with', required=True)
parser.add_argument('-dd', '--docker-dirs', help='The docker dirs that were changed', required=True)


def trigger_pipeline(target_image: str, circle_token: str):

    #payload = f'{{\"branch\":\"master\",\"parameters\":{{\"docker_image_target\":\"{target_image}\"}}}}'
    payload = f'{{\"branch\":\"add_dockerfiles_lint_trigger\",\"parameters\":{{\"docker_image_target\":\"{target_image}\"}}}}'

    headers = {
        'content-type': "application/json",
        'Circle-Token': circle_token
    }

    # res = requests.post(f"{CIRCLE_ADDRESS}/{API_PROJECT_URL}/pipeline", data=payload, headers=headers)
    res = requests.post(f"{CIRCLE_ADDRESS}/{API_PROJECT_URL}/pipeline", data=payload, headers=headers, verify=False)

    data = res.text

    try:
        pipeline_data = json.loads(data)
    except Exception as err:
        logging.error(f'Could not parse circle response: {str(err)}')
        raise err

    pipeline_number = pipeline_data.get("number")

    if not pipeline_number:
        raise Exception(f"Could not trigger pipeline: {pipeline_data.get('message')}")

    return pipeline_number


def get_pipeline_state(pipeline_num: str, circle_token: str):
    headers = {
        'Circle-Token': circle_token
    }

    # res = requests.get(f"{CIRCLE_ADDRESS}/{API_PROJECT_URL}/pipeline/{pipeline_num}", headers=headers)
    res = requests.get(f"{CIRCLE_ADDRESS}/{API_PROJECT_URL}/pipeline/{pipeline_num}", headers=headers, verify=False)

    data = res.text

    try:
        pipeline_data = json.loads(data)
    except Exception as err:
        logging.error(f'Could not parse circle status response: {str(err)}')
        raise err

    pipeline_state = pipeline_data.get("state")

    if not pipeline_state:
        raise Exception(f"Could not poll pipeline status: {pipeline_data.get('message')}")

    return pipeline_state


def get_pipeline_url(pipeline_num: str):
    return f"{PIPELINE_URL_PREFIX}/{pipeline_num}"


def main(target_image: str, circle_token: str, docker_dirs: str):
    logging.info(f'Checking if changed dockerfiles are of native image')
    docker_dirs_list = docker_dirs.split("\n")
    logging.info(f'Changed docker dirs found: {docker_dirs_list}')
    if NATIVE_IMAGE_NAME not in docker_dirs_list:
        logging.info(f'No changes were found to native image. Not Running.')
        sys.exit(0)

    logging.info(f'Triggering lint for native supported content with target image {target_image}')
    triggered, pipeline_num = trigger_pipeline(target_image, circle_token)
    pipeline_url = get_pipeline_url(pipeline_num)
    logging.info(f'------ Pipeline Created At: {pipeline_url} ------')
    get_pipeline_retry_number = 0

    while get_pipeline_retry_number < GET_PIPELINES_MAX_RETRIES:
        logging.info('Getting pipeline status...')
        state = get_pipeline_state(pipeline_num, circle_token)
        if state == "success":
            logging.info('Pipeline Finished Successfully')
            logging.info(f'Pipeline url: {pipeline_url}')
            sys.exit(0)

        elif state not in ("running", "queued"):
            logging.error(f'Pipeline Finished with state {state}')
            logging.error(f'Pipeline url: {pipeline_url}')
            sys.exit(1)

        get_pipeline_retry_number += 1
        # wait 5 seconds before next polling.
        time.sleep(5)

    logging.error(f'Maximum timeout reached for Pipeline. Abandoning Build.')
    logging.error(f'Pipeline url: {pipeline_url}')
    sys.exit(1)


def testing_main(target_image: str, circle_token: str, docker_dirs: str):
    logging.info(f"target_image {target_image}, docker_dirs {docker_dirs}")


if __name__ == "__main__":
    args = parser.parse_args()
    logging.getLogger().addHandler(logging.StreamHandler())
    logging.getLogger().setLevel(logging.INFO)
    logging.info("Starting trigger lint on native content script")
    main(target_image=args.target_image, circle_token=args.circle_token, docker_dirs=args.docker_dirs)
