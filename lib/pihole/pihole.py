# from this import s
from urllib import parse as urlparse

import logging
from collections import defaultdict
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, BaseConfig
from typing import Optional, List
from pprint import pprint, pformat

from .base import BaseHTTPHandler

from pihole6api import PiHole6Client
# from ..dependencies import get_token_header

# import http.client as http_client

# http_client.HTTPConnection.debuglevel = 0

# You must initialize logging, otherwise you'll not see debug output.


# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True
logger: logging.Logger | None = None


class PiHoleOverlord(BaseHTTPHandler):
    app_config: dict
    piList: List[str]
    domains: dict
    block_domains: dict
    allow_domains: dict
    timer: int  # unused, FIXME for optional fields in base class
    sessions: dict[str, PiHole6Client]

    def __init__(self, app_config: dict) -> None:
        super().__init__(
            app_config=app_config,
        )
        global logger
        logger = app_config["logger"]

    # def add(
    #     self, phList, domain, groups=None, enabled=True, comment=None, pi="localpi"
    # ):
    #     for _, pi in self.sessions.items():
    #         rez = pi.domain_management.add_domain(domain, "deny", "regex")
    #         logger.debug(f"Add domain response: {rez}")
    #     return {"status": "ok"}

    # def sub(
    #     self, phList, domain, groups=None, enabled=True, comment=None, pi="localpi"
    # ):
    #     for _, pi in self.sessions.items():
    #         rez = pi.domain_management.delete_domain(domain, "deny", "regex")
    #         logger.debug(f"Add domain response: {rez}")
    #     return {"status": "ok"}

    # def sGet(self, domain_block=None, pi="localhost"):
    #     response = self.cmd(method="get", cmd="list", phList="regex_black", pi=pi)
    #     return response

    def get(self, domain_block=None):
        # resps = list()
        # whitelist = dict()
        # blacklist = dict()
        # for _, pi in self.sessions.items():
        #     resp = pi.domain_management.get_all_domains()
        #     logger.debug(f"Got response: {pformat(resp)}")
        #     for domain, val in resp["whitelist"].items():
        #         if domain not in whitelist:
        #             whitelist[domain] = val
        #         if val != whitelist[domain]:
        #             logger.warning(
        #                 f"Whitelist mismatch for {domain}: {val} != {whitelist[domain]}"
        #             )
        #             return {"status": "Unknown"}

        #     for domain, val in resp["blacklist"].items():
        #         if domain not in blacklist:
        #             blacklist[domain] = val
        #         if val != blacklist[domain]:
        #             logger.warning(
        #                 f"Blacklist mismatch for {domain}: {val} != {blacklist[domain]}"
        #             )
        #             return {"status": "Unknown"}

        if domain_block is None or (domain_block not in self.block_domains and domain_block not in self.allow_domains):
            return {"status": "Unknown"}
        if not self.logged_in:
            logger.debug("Not logged in, logging in...")
            self.first_connect()
        states = set()
        control_type: str = "deny"
        logger.debug(f"Checking status {domain_block}")
        if domain_block in self.allow_domains:
            control_type = "allow"
            logger.debug(f"Using allow control for {domain_block}")
        for domain in self.domains[control_type][domain_block]:
            logger.debug("%s -> %s" % (domain, self.transform(domain)))
            #            pprint(self.transform(domain))
            for _, pi in self.sessions.items():
                record = self.domain_record(pi, domain, control_type)
                states.add(bool(record and record["enabled"]))
        if len(states) != 1:
            return {"status": "unknown"}
        return {"status": str(states.pop()).lower()}

    def domain_record(self, pi, domain, control_type):
        response = pi.domain_management.get_domain(domain, control_type, "regex")
        if not isinstance(response, dict) or "error" in response or "domains" not in response:
            raise HTTPException(status_code=502, detail="Cannot read Pi-hole domain state")
        records = response["domains"]
        if not records:
            return None
        if len(records) != 1 or records[0].get("domain") != domain or "enabled" not in records[0]:
            raise HTTPException(status_code=502, detail="Unexpected Pi-hole domain state")
        return records[0]

    def post(
        self,
        direction: str,
        domain_block: str | None = None,
    ):
        if not domain_block or (domain_block not in self.block_domains and domain_block not in self.allow_domains):
            logger.error("No domain block specified")
            raise HTTPException(status_code=404, detail="Domain Block not configured")
        if direction not in ("enable", "disable"):
            raise HTTPException(status_code=404, detail="Unknown direction")
        if not self.logged_in:
            logger.debug("Not logged in, logging in...")
            self.first_connect()
        control_type: str = "deny"
        logger.debug(f"Checking status {domain_block}")
        if domain_block in self.allow_domains:
            control_type = "allow"
            logger.debug(f"Using allow control for {domain_block}")

        logger.info(f"Request to {direction} {control_type} {domain_block}")
        for _, pi in self.sessions.items():
            for domain in self.domains[control_type][domain_block]:
                record = self.domain_record(pi, domain, control_type)
                if direction == "disable" and record:
                    pi.domain_management.delete_domain(domain, control_type, "regex")
                elif direction == "enable":
                    if record is None:
                        pi.domain_management.add_domain(domain, control_type, "regex", groups=[0])
                    elif not record["enabled"]:
                        pi.domain_management.update_domain(
                            domain, control_type, "regex", enabled=True,
                            groups=record.get("groups", [0]), comment=record.get("comment"),
                        )
        observed = self.get(domain_block)
        expected = "true" if direction == "enable" else "false"
        if observed["status"] != expected:
            raise HTTPException(status_code=502, detail="Pi-hole domain state did not converge")
        return observed
