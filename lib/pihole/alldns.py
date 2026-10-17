import requests
import hashlib
from urllib import parse as urlparse
import urllib3
import re
import sys
import os
import json

import logging
import configparser
from collections import defaultdict
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, BaseConfig
from typing import Optional, List
from pprint import pprint, pformat

from .base import BaseHTTPHandler
from pihole6api import PiHole6Client

# from ..dependencies import get_token_header
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
# logger.debug("Stated up all_dns")


class MasterEnabler(BaseHTTPHandler):
    app_config: dict
    piList: List[str]
    domains: dict
    timer: int
    sessions: dict

    #        self.reqparse = reqparse.RequestParser()
    ### FIXME
    #        self.reqparse.add_argument("disable_timer", type=int, default=None)
    #        self.timer = 0
    def __init__(self, app_config: dict) -> None:
        super().__init__(app_config=app_config)
        global logger
        logger = app_config["logger"]
        logger.debug("Started up all_dns")

    # def cmd(
    #     self, cmd=None, phList=None, pi=None, domain=None, comment=None, method="post"
    # ):
    #     if not self.logged_in:
    #         logger.debug("Not logged in, logging in...")
    #         self.first_connect()
    #     url = "/admin/api.php"
    #     gArgs = {"auth": self.token}
    #     pArgs = {}
    #     if not cmd:
    #         return
    #     if cmd == "disable" or cmd == "enable":
    #         gArgs[cmd] = self.timer
    #         qs = urlparse.urlencode(gArgs)
    #     else:
    #         qs = cmd
    #     #        print(qs)

    #     furl = "http://" + str(pi) + url + "?" + qs
    #     pprint(furl)
    #     logger.debug(f"'{furl}' and cookies {self.sessions[pi].cookies}")
    #     if method == "get":
    #         temp = self.sessions[pi].get(furl)
    #         logger.debug(temp.json())
    #         return temp.json()
    #     temp = self.sessions[pi].post(furl, data=pArgs)
    #     logger.debug(temp.text)
    #     return temp.json()

    def flip_mode(self, status: bool, timer: int | None = None):
        logger.debug(f"Flipping DNS blocking to {'enabled' if status else 'disabled'}")
        if not self.logged_in:
            logger.debug("Not logged in, logging in...")
            self.first_connect()
        for _, pi in self.sessions.items():
            response = pi.dns_control.set_blocking_status(status, timer)
            if isinstance(response, dict) and "error" in response:
                raise HTTPException(status_code=502, detail="Pi-hole rejected blocking change")
        observed = self.get()
        if observed["status"] != str(status).lower():
            raise HTTPException(status_code=502, detail="Pi-hole blocking state did not converge")
        return observed

    def disable_dns_blocking(self, timer=None):
        return self.flip_mode(status=False, timer=timer or None)
        # {'blocking': 'disabled', 'timer': 60 ...}

    def enable_dns_blocking(self):
        return self.flip_mode(status=True)

    def get(self):
        stateMap = {"enabled": "true", "disabled": "false"}
        logger.debug("Getting DNS blocking status")
        if not self.logged_in:
            logger.debug("Not logged in, logging in...")
            self.first_connect()
        retv = list()
        for _, pi in self.sessions.items():
            logger.debug(f"Getting DNS status on {type(pi)}")
            status = pi.dns_control.get_blocking_status()
            if not isinstance(status, dict) or status.get("blocking") not in stateMap:
                raise HTTPException(status_code=502, detail="Cannot read Pi-hole blocking state")
            retv.append(status["blocking"])
        if len(set(retv)) != 1:
            logger.warning("Inconsistent states detected among devices")
            logger.warning(f"States: {pformat(retv)}")
            return {"status": "unknown"}  #        self.cmd("disable, None, pi)
        return {"status": stateMap[retv[0]]}

        # stateMap = {"enabled": "on", "disabled": "off"}
        # ## enumerate states, accounting for fact some states might be different between devices...
        # for piResp in resps:
        #     translated = stateMap[piResp["status"]]
        #     #           translated = "disabled"
        #     sumResp[translated].append(translated)
        # # FIXME: Can HomeKit represent this???
        # if len(sumResp.keys()) > 1:
        #     return {"status": "off"}
        # logger.info({"status": list(sumResp.keys())[0]})

        # return {"status": list(sumResp.keys())[0]}
