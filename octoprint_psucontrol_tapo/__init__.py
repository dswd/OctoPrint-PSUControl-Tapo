# coding=utf-8
from __future__ import absolute_import
import threading

__author__ = "Dennis Schwerdel <schwerdel@gmail.com>"
__license__ = "GNU Affero General Public License http://www.gnu.org/licenses/agpl.html"
__copyright__ = "Copyright (C) 2022 Dennis Schwerdel - Released under terms of the AGPLv3 License"

import octoprint.plugin
from .tapo import P100
from . import tapo

class PSUControl_Tapo(octoprint.plugin.StartupPlugin,
                      octoprint.plugin.RestartNeedingPlugin,
                      octoprint.plugin.TemplatePlugin,
                      octoprint.plugin.SettingsPlugin):

    def __init__(self):
        self.config = dict()
        self.device = None
        self.last_status = None


    def get_settings_defaults(self):
        return dict(
            address = '',
            username = '',
            password = ''
        )


    def on_settings_initialized(self):
        self.reload_settings()


    def on_settings_save(self, data):
        octoprint.plugin.SettingsPlugin.on_settings_save(self, data)
        self.reload_settings()


    def get_settings_version(self):
        return 1


    def on_settings_migrate(self, target, current=None):
        pass


    def _reconnect(self):
        self._logger.info(f"Connecting to Tapo device at {self.config['address']}")
        self.device = P100(self.config["address"], self.config["username"], self.config["password"])

    def reload_settings(self):
        for k, v in self.get_settings_defaults().items():
            if type(v) == str:
                v = self._settings.get([k])
            elif type(v) == int:
                v = self._settings.get_int([k])
            elif type(v) == float:
                v = self._settings.get_float([k])
            elif type(v) == bool:
                v = self._settings.get_boolean([k])

            self.config[k] = v
            self._logger.debug("{}: {}".format(k, v))
        try:
            self._logger.info(f"Config: {self.config}")
            tapo.log = self._logger
            self._reconnect()
        except:
            self._logger.exception(f"Failed to connect to Tapo device")


    def on_startup(self, host, port):
        psucontrol_helpers = self._plugin_manager.get_helpers("psucontrol")
        if not psucontrol_helpers or 'register_plugin' not in psucontrol_helpers.keys():
            self._logger.warning("The version of PSUControl that is installed does not support plugin registration.")
            return

        self._logger.debug("Registering plugin with PSUControl")
        psucontrol_helpers['register_plugin'](self)


    def turn_psu_on(self):
        if not self.device:
            self._reconnect()
        self._logger.debug("Switching PSU On")
        try:
            self.device.set_status(True)
            self.last_status = True
        except:
            self._logger.exception(f"Failed to switch PSU On")
            self.device = None
            raise

    def turn_psu_off(self):
        if not self.device:
            self._reconnect()
        self._logger.debug("Switching PSU Off")
        try:
            self.device.set_status(False)
            self.last_status = False
        except:
            self._logger.exception(f"Failed to switch PSU Off")
            self.device = None
            raise


    def _fetch_psu_state(self):
        if not self.device:
            self._reconnect()
        self._logger.debug("get_psu_state")
        try:
            self.last_status = self.device.get_status()
        except:
            self._logger.exception(f"Failed to get PSU state")
            self.device = None
            raise

    def get_psu_state(self):
        if not self.last_status:
            self._fetch_psu_state()
        else:
            threading.Thread(target=self._fetch_psu_state).start()
        return self.last_status

    def get_template_configs(self):
        return [
            dict(type="settings", custom_bindings=False)
        ]


    def get_update_information(self):
        return dict(
            psucontrol_tapo=dict(
                displayName="PSU Control - Tapo",
                displayVersion=self._plugin_version,

                # version check: github repository
                type="github_release",
                user="dswd",
                repo="OctoPrint-PSUControl-Tapo",
                current=self._plugin_version,

                # update method: pip w/ dependency links
                pip="https://github.com/dswd/OctoPrint-PSUControl-Tapo/archive/{target_version}.zip"
            )
        )

__plugin_name__ = "PSU Control - Tapo"
__plugin_pythoncompat__ = ">=2.7,<4"

def __plugin_load__():
    global __plugin_implementation__
    __plugin_implementation__ = PSUControl_Tapo()

    global __plugin_hooks__
    __plugin_hooks__ = {
        "octoprint.plugin.softwareupdate.check_config": __plugin_implementation__.get_update_information
    }
