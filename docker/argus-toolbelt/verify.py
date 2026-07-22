import html
import json
import logging
import mimetypes
import traceback
from typing import Any

import dateparser
import urllib3
from argus_api import session as argus_session
from argus_api.exceptions.http import AccessDeniedException
from argus_api.lib.cases.v2.case import (
    add_attachment,
    add_case_tag,
    add_comment,
    advanced_case_search,
    close_case,
    create_case,
    delete_case,
    delete_comment,
    download_attachment,
    edit_comment,
    get_attachment,
    get_case_metadata_by_id,
    list_case_attachments,
    list_case_comments,
    list_case_tags,
    remove_case_tag_by_id,
    remove_case_tag_by_key_value,
    update_case,
)
from argus_api.lib.currentuser.v1.user import get_current_user
from argus_api.lib.events.v1 import get_event_by_path
from argus_api.lib.events.v1.aggregated import (
    find_aggregated_events,
    list_aggregated_events,
)
from argus_api.lib.events.v1.case.case import get_events_for_case
from argus_api.lib.events.v1.nids import find_nids_events, list_nids_events
from argus_api.lib.events.v1.payload import get_payload
from argus_api.lib.events.v1.pcap import get_pcap
from argus_api.lib.pdns.v3.search import search_records
from argus_api.lib.reputation.v1.observation import (
    fetch_observations_for_domain,
    fetch_observations_for_ip,
)

print("All is well in the world of Argus API")