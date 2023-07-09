import codecs
import contextlib
import datetime
import logging
from typing import Any, Generator, List, Tuple
import struct

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers.physical import BufferDataLayer
from volatility3.framework.layers.registry import RegistryHive
from volatility3.framework.renderers import conversion, format_hints
from volatility3.framework.symbols import intermed
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


class OsInfos(interfaces.plugins.PluginInterface):
    """Print RecentDocs registry keys and information."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.IntRequirement(
                name="offset", description="Hive Offset", default=None, optional=True
            ),
            requirements.PluginRequirement(
                name="hivelist", plugin=hivelist.HiveList, version=(1, 0, 0)
            ),
        ]

    # main method:
    def list_osversion(self, hive: RegistryHive) -> Generator[Tuple[int, Tuple], None, None]:
        """Generate os infos data for a registry hive."""

        kernel = self.context.modules[self.config["kernel"]]

        hive_name = hive.hive.cast(kernel.symbol_table_name + constants.BANG + "_CMHIVE").get_name()

        # Description: OS Infos
        # HiveType: SOFTWARE
        # Category: OS Infos
        # KeyPath: Microsoft\Windows NT\CurrentVersion
        version_node_path = hive.get_key(
            "Microsoft\\Windows NT\\CurrentVersion",       
            return_list=True,
        )

        if not version_node_path:
            vollog.warning("list_osversion did not find a valid node_path (or None)")
            return

        if not isinstance(version_node_path, list):
            vollog.warning("version_node_path did not return a list as expected")
            return

        # go through all nodes;
        for node in version_node_path:

            # Get Last Write Time
            writetime = conversion.wintime_to_datetime(node.LastWriteTime.QuadPart)
            description = "System Info (Current)"
            # iterate through all values
            for value in node.get_values():

                # Get Value Name:
                value_name = value.get_name()
                if(value_name in [ "SystemRoot", "RegisteredOwner", "RegisteredOrganization", "InstallTime", "ProductName", "InstallDate", "InstallationType", "EditionID", "CurrentMajorVersionNumber", "CurrentBuildNumber", "CurrentBuild", "CompositionEditionID", "BuildLab" ]):

                    # Get Data:
                    try:
                        value_data = (value.decode_data().decode('utf-16le'))
                    except:
                        value_data = str(value.decode_data())

                    result = (
                        0, #TreeDepth
                            (
                                renderers.format_hints.Hex(hive.hive_offset), # Hive Offset
                                hive.name if hive.name else renderers.UnreadableValue(), # ,Hive Name
                                value_name if value_name else renderers.UnreadableValue(),
                                value_data if value_data else renderers.UnreadableValue(),
                                description if description else renderes.UnreadableValue(),
                                writetime if writetime else renderes.UnreadableValue(),
                            ),
                        )
                    yield result

    def get_computername(self, hive: RegistryHive) -> Generator[Tuple[int, Tuple], None, None]:
        """Generate computername data for a registry hive."""

        #kernel = self.context.modules[self.config["kernel"]]

       # hive_name = hive.hive.cast(kernel.symbol_table_name + constants.BANG + "_CMHIVE").get_name()


        # Description: Computer Name
        # HiveType: SOFTWARE
        # Category: OS Infos
        # KeyPath: ControlSet001\Control\ComputerName\ComputerName
        node_path = hive.get_key(
            "ControlSet001\\Control\\ComputerName\\ComputerName",       
            return_list=True,
        )

        if not node_path:
            vollog.warning("get_computername did not find a valid node_path (or None)")
            return

        if not isinstance(node_path, list):
            vollog.warning("node_path did not return a list as expected")
            return

        # go through all nodes;
        for node in node_path:

            # Get Last Write Time
            writetime = conversion.wintime_to_datetime(node.LastWriteTime.QuadPart)
            description = "System Info (Current)"
            # iterate through all values
            for value in node.get_values():

                # Get Value Name:
                value_name = value.get_name()
                if(value_name in [ "ComputerName" ]):

                    # Get Data:
                    try:
                        value_data = (value.decode_data().decode('utf-16le'))
                    except:
                        value_data = str(value.decode_data())

                    result = (
                        0, #TreeDepth
                            (
                                renderers.format_hints.Hex(hive.hive_offset), # Hive Offset
                                hive.name if hive.name else renderers.UnreadableValue(), # ,Hive Name
                                value_name if value_name else renderers.UnreadableValue(),
                                value_data if value_data else renderers.UnreadableValue(),
                                description if description else renderes.UnreadableValue(),
                                writetime if writetime else renderes.UnreadableValue(),
                            ),
                        )
                    yield result
                    break;
    
    def _generator(self):
        hive_offsets = None
        if self.config.get("offset", None) is not None:
            hive_offsets = [self.config.get("offset", None)]
        kernel = self.context.modules[self.config["kernel"]]

        # Get Software Hive
        for hive in hivelist.HiveList.list_hives(
            context=self.context,
            base_config_path=self.config_path,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_string=None,
            hive_offsets=hive_offsets,
        ):

            if ("SOFTWARE" in hive.get_name()):
                try:
                    # try getting information from hive by running
                    yield from self.list_osversion(hive)
                    continue
                except exceptions.PagedInvalidAddressException as excp:
                    vollog.debug(f"Invalid address identified in Hive: {hex(excp.invalid_address)}")
                except exceptions.InvalidAddressException as excp:
                    vollog.debug("Invalid address identified in lower layer {}: {}".format(excp.layer_name, excp.invalid_address))
                except KeyError:
                    vollog.debug("Key '{}' not found in Hive at offset {}.".format(
                            "software\\microsoft\\windows\\currentversion",hex(hive.hive_offset),
                        )
                    )

                # yield UnreadableValues when an exception occurs for a given hive_offset
                result = (
                    0, #TreeDepth
                    (
                        renderers.format_hints.Hex(hive.hive_offset), # Hive Offset
                        hive.name if hive.name else renderers.UnreadableValue(), # ,Hive Name
                        value_name if value_name else renderers.UnreadableValue(),
                        value_data if value_data else renderers.UnreadableValue(),
                        description if description else renderes.UnreadableValue(),
                        writetime if writetime else renderes.UnreadableValue(),
                    ),
                )
                yield result

            if ("SYSTEM" in hive.get_name()):
       
                try:
                    # try getting information from list_recentdocs method
                    yield from self.get_computername(hive)
                    continue
                except exceptions.PagedInvalidAddressException as excp:
                    vollog.debug(f"Invalid address identified in Hive: {hex(excp.invalid_address)}")
                except exceptions.InvalidAddressException as excp:
                    vollog.debug("Invalid address identified in lower layer {}: {}".format(excp.layer_name, excp.invalid_address))
                except KeyError:
                    vollog.debug("Key '{}' not found in Hive at offset {}.".format(
                            "ControlSet001\\Control\\ComputerName\\ComputerName",hex(hive.hive_offset),
                        )
                    )

                # yield UnreadableValues when an exception occurs for a given hive_offset
                result = (
                    0, #TreeDepth
                    (
                        renderers.format_hints.Hex(hive.hive_offset), # Hive Offset
                        hive.name if hive.name else renderers.UnreadableValue(), # ,Hive Name
                        value_name if value_name else renderers.UnreadableValue(),
                        value_data if value_data else renderers.UnreadableValue(),
                        description if description else renderes.UnreadableValue(),
                        writetime if writetime else renderes.UnreadableValue(),
                    ),
                )
                yield result

    def run(self):
        self._reg_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self._config_path, "windows", "registry"
        )

        return renderers.TreeGrid(
            [
                ("HiveOffset", renderers.format_hints.Hex),
                ("HiveName", str),
                ("ValueName", str),
                ("ValueData", str),
                ("Description", str),
                ("LastWriteTime", datetime.datetime)
            ],
            self._generator(),
        )
