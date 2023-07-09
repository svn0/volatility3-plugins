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


class RecentDocs(interfaces.plugins.PluginInterface):
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
    def list_recentdocs(
        self, hive: RegistryHive
    ) -> Generator[Tuple[int, Tuple], None, None]:
        """Generate recent docs data for a registry hive."""

        kernel = self.context.modules[self.config["kernel"]]

        hive_name = hive.hive.cast(kernel.symbol_table_name + constants.BANG + "_CMHIVE").get_name()

        # Description: RecentDocs
        # HiveType: NtUser
        # Category: User Activity
        # KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
        recentdocs_node_path = hive.get_key(
            "software\\microsoft\\windows\\currentversion\\explorer\\recentdocs",       
            return_list=True,
        )

        if not recentdocs_node_path:
            vollog.warning("list_recentdocs did not find a valid node_path (or None)")
            return

        if not isinstance(recentdocs_node_path, list):
            vollog.warning("recentdocs_node_path did not return a list as expected")
            return

        # Select Recent Docs Key
        recentdocs_node = recentdocs_node_path[-1]
        
        # Get Last Write Time
        recentdocs_writetime = conversion.wintime_to_datetime(recentdocs_node.LastWriteTime.QuadPart)

        #print(len(recentdocs_node.get_values()))
        # iterate through the RecentDocs key
        for value in recentdocs_node.get_values():

            # Get Extension
            extension = recentdocs_node.get_name()

            # Get Value Name:
            value_name = value.get_name()

            # Get Data:
            data = value.decode_data()

            target_name = ""

            # Figure out order of recent items:
            if (value_name == "MRUListEx"):

                # In order to figure out the order we need to parse (use struct to conert to integers)
                numbers = [struct.unpack('<I', data[i:i+4])[0] for i in range(0, len(data)-4, 4)]
            
            # If its not MRUListEx it means we have on of the RecentDoc Entries (name = number, value equals target name and lnk filename, etc..)
            else:

                # clear timestamps
                last_opened = None
                exension_last_opened = None

                # Split into different parts:
                parts = data.split(b'\x00\x00')
                
                # Get target name
                target_name = parts[0].decode('ascii')
                # Get link file name
                lnk_name = parts[-3].decode('ascii')

                # Get MRU position:
                mru_position = "-1"
                for idx, item in enumerate(numbers):
                    if (int(item) == int(value_name)):
                        mru_position = int(idx)
                        # add last openend date for most recent item
                        if (mru_position == 0):
                            last_opened = recentdocs_writetime
                            exension_last_opened = recentdocs_writetime
               

                result = (
                    0, #TreeDepth
                        (
                            renderers.format_hints.Hex(hive.hive_offset), # Hive Offset
                            hive.name if hive.name else renderers.UnreadableValue(), # ,Hive Name
                            extension if extension else renderers.UnreadableValue(), # Extension
                            value_name if value_name else renderes.UnreadableValue(), # Value Name
                            target_name if target_name else renderers.UnreadableValue(), # Target Name
                            lnk_name if lnk_name else renderers.UnreadableValue(), # LNK Name
                            mru_position if mru_position else renderers.UnreadableValue(), # MRU Position
                            last_opened if last_opened else renderers.UnreadableValue(), # Opened On
                            exension_last_opened if exension_last_opened else renderers.UnreadableValue(), # Extension Last Opened
                        ),
                    )
                yield result

        # iterate through the RecentDocs subkeys (per extension)
        for subkey in recentdocs_node.get_subkeys():
            
            # get extension:
            extension = subkey.get_name()
          
            # key path:
            extension_path = subkey.get_key_path()
            
            # last write time:
            extension_writetime = conversion.wintime_to_datetime(subkey.LastWriteTime.QuadPart)

            for value in subkey.get_values():
                
                # Get Value Name
                value_name = value.get_name()

                # Figure out order of recent items:
                if (value_name == "MRUListEx"):
                    data = value.decode_data()
                    numbers = [struct.unpack('<I', data[i:i+4])[0] for i in range(0, len(data)-4, 4)]

                else:
                    data = value.decode_data()

                    # Split into different parts:
                    parts = data.split(b'\x00\x00')

                    # get target name
                    target_name = parts[0].decode('ascii')

                    # get link file name
                    lnk_name = parts[-3].decode('ascii')

                    exension_last_opened = None
                    # Get MRU position:
                    mru_position = "-1"
                    for idx, item in enumerate(numbers):
                        if (int(item) == int(value_name)):
                            mru_position = int(idx)
                            # add last openend date for most recent item
                            if (mru_position == 0):
                                exension_last_opened = extension_writetime

                    result = (
                        0, #TreeDepth
                            (
                                renderers.format_hints.Hex(hive.hive_offset), # Hive Offset
                                hive.name if hive.name else renderers.UnreadableValue(), # ,Hive Name
                                extension if extension else renderers.UnreadableValue(), # Extension
                                value_name if value_name else renderes.UnreadableValue(), # Value Name
                                target_name if target_name else renderers.UnreadableValue(), # Target Name
                                lnk_name if lnk_name else renderers.UnreadableValue(), # LNK Name
                                mru_position if mru_position else renderers.UnreadableValue(), # MRU Position
                                renderers.UnreadableValue(), # Opened On
                                exension_last_opened if exension_last_opened else renderers.UnreadableValue(), # Extension Last Opened
                            ),
                        )
                    yield result

    def _generator(self):
        hive_offsets = None
        if self.config.get("offset", None) is not None:
            hive_offsets = [self.config.get("offset", None)]
        kernel = self.context.modules[self.config["kernel"]]

        # get all the user hive offsets or use the one specified
        for hive in hivelist.HiveList.list_hives(
            context=self.context,
            base_config_path=self.config_path,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_string="ntuser.dat",
            hive_offsets=hive_offsets,
        ):
            try:
                # try getting information from list_recentdocs method
                yield from self.list_recentdocs(hive)
                continue
            except exceptions.PagedInvalidAddressException as excp:
                vollog.debug(f"Invalid address identified in Hive: {hex(excp.invalid_address)}")
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Invalid address identified in lower layer {}: {}".format(excp.layer_name, excp.invalid_address))
            except KeyError:
                vollog.debug("Key '{}' not found in Hive at offset {}.".format(
                        "software\\microsoft\\windows\\currentversion\\explorer\\recentdocs",hex(hive.hive_offset),
                    )
                )

            # yield UnreadableValues when an exception occurs for a given hive_offset
            result = (
                0, #TreeDepth
                (
                    renderers.format_hints.Hex(hive.hive_offset), # Hive Offset
                    hive.name if hive.name else renderers.UnreadableValue(), # ,Hive Name
                    renderers.UnreadableValue(), # Extension
                    renderers.UnreadableValue(), # Value Name
                    renderers.UnreadableValue(), # Target Name
                    renderers.UnreadableValue(), # LNK Name
                    renderers.UnreadableValue(), # MRU Position
                    renderers.UnreadableValue(), # Opened On
                    renderers.UnreadableValue(), # Extension Last Opened
                ),
            )
            yield result

    def run(self):
        self._reg_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self._config_path, "windows", "registry"
        )

        return renderers.TreeGrid(
            [
                ("Hive Offset", renderers.format_hints.Hex),
                ("Hive Name", str),
                ("Exension", str),
                ("Value Name", str),
                ("Target Name", str),
                ("Lnk Name", str),
                ("MRU Position", int),
                ("Opened On", datetime.datetime),
                ("Extension Last Opened", datetime.datetime),
            ],
            self._generator(),
        )
