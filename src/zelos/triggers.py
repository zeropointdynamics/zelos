# Copyright (C) 2020 Zeropoint Dynamics

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
# ======================================================================

import time

from collections import defaultdict
from enum import Enum


class RuleType(Enum):
    NORMAL = 1
    TABLE = 2


class Trigger:
    """
    Triggers represent an action taken by a binary that is worth
    recording.
    """

    def __init__(self, name, details, tags):
        self.name = name
        self.tags = tags
        if len(self.tags) == 0:
            self.tags.append("Misc")

        self.details = defaultdict(int)
        if details is not None:
            self.details[details] = 1

    def add_occurrence(self, details):
        if details is not None:
            self.details[details] += 1

    def clear_details(self):
        self.details = defaultdict(int)


class TableTrigger(Trigger):
    def __init__(self, name, details, column_names, tags):
        Trigger.__init__(self, name, details, tags)
        self.column_names = column_names


class Triggers:
    """
    Manages triggers that are given to the Reporter for the purpose of
    Report Generation
    """

    def __init__(self, z):
        self.z = z
        self.rules = {}
        self.groupings = [
            # 'Lineage Analysis',
            "Yara Rules",
            "Network Activity",
            "Process Manipulation",
            "Registry Key Manipulation",
            "File System",
            "Misc",
            "Thread Report",
        ]
        self.reached_entrypoint = False
        self.seen_rdtsc = False

        self.total_time_slept_in_ms = 0
        self.update_time = time.time()
        self.num_syscalls_called = 0
        self.unique_domains = set()
        self.process_write_message = "Process Write: "
        self.registry_create_key_message = "Registry Create: "
        self.registry_key_write_message = "Registry Write: "
        self.load_library_message = "Load library: "
        self.rdtsc_message = (
            "Evasion: Anti-debug technique detected (RDTSC timing method)"
        )
        self.exec_unpacked = False
        self.exec_unpacked_message = "Evasion: Detected unpacked code exection"
        self.rpc_message = "Remote Procedure Call: "
        # thread_name -> [Api()]
        self.apis_called = defaultdict(list)
        self.api_strings = set()
        self.syscalls_called = defaultdict(list)

    def _update_msg(self):
        blocks = self.z.emu.bb_count()
        if blocks % 10000 != 0 or blocks == 0:
            return

        curr_time = time.time()
        if curr_time - self.update_time >= 1:
            self.update_time = curr_time
            unique_blocks = self.z.current_process.blocks_executed()
            self._custom_print(
                f"Blocks: {blocks}, Unique_blocks: {unique_blocks}, "
                f"Syscalls {self.num_syscalls_called}, Time Slept (s): "
                f"{round(self.total_time_slept_in_ms/1000)}"
            )

    def _custom_print(self, msg):
        # Used just for the hackathon
        self.update_time = time.time()
        if self.z.current_thread is not None:
            name = self.z.current_thread.name
            if "|" in name:
                name = name.split("|")[0]
            print(f"[HIGHLIGHTS] [{name}]: {msg}")

    def update_trigger(self, name, details, grouping="Misc", tags=[]):
        if name not in self.rules:
            self.trigger(name, details, tags, grouping)
            return
        self.rules[name].clear_details()
        self.rules[name].add_occurrence(details)

    def trigger(
        self,
        name,
        details=None,
        tags=None,
        rule_type=RuleType.NORMAL,
        type_info=None,
        grouping="Misc",
    ):
        """ Register a rule which has been triggered."""
        # Keep track of what groupings have been used
        if grouping not in self.groupings:
            self.groupings.append(grouping)
        tags = [] if tags is None else tags
        tags.append(grouping)

        if name not in self.rules:
            if rule_type == RuleType.NORMAL:
                self.rules[name] = Trigger(name, details, tags)
            elif rule_type == RuleType.TABLE:
                self.rules[name] = TableTrigger(name, details, type_info, tags)
        else:
            self.rules[name].add_occurrence(details)

        # Update the file if the report directory is specified
        # if len(self.report_filepath) > 0:
        #     self.gen_report(filename=self.report_filepath)

    # TODO
    # Tree overall for all threads
    # Report for individual thread
    # Report for all threads.

    # Collect names from mutex, semaphore, events, atoms (others...)
    # Setting memory to writable / executable
    #   in virtual protect / virtualalloc
    # Reading the stack values to get the address of kernel32
    #   (stack values prior to execution)

    # Manual parsing of peb loader list

    def tr_read_peb(self, eip):
        pass  # This seems to be done in most binaries actually.
        # self.trigger('Reads Process Environment Block (PEB)',
        # 'Read PEB from eip = 0x{0:x}'.format(eip),
        # grouping='PEB Access', tags=['evasive'])

    def tr_read_peb_ldr(self, eip):
        self.trigger(
            "Implements custom Import/GetProcAddress API",
            "Read PEB_LDR_LIST from eip = 0x{0:x}".format(eip),
            tags=["evasive"],
        )

    # Any kind of network activity, using sockets
    def tr_contacts_domain(self, domain_name, method_name):
        # Contacting domains isn't suspicious by itself,
        # but certain patterns are
        #  - Contacting random looking domains
        #  - Contacting known malicious domains
        max_printed_domains = 10
        self.trigger(
            "Contacts domain",
            "Connects to %s using %s" % (domain_name, method_name),
            grouping="Network Activity",
        )
        if (
            len(self.unique_domains) < max_printed_domains
            and domain_name not in self.unique_domains
        ):
            self._custom_print(f'DNS QUERY: "{domain_name}"')
        if len(self.unique_domains) == max_printed_domains:
            self._custom_print(
                f"DNS QUERY: Suppressing additional query output"
            )
        self.unique_domains.add(domain_name)
        if len(self.unique_domains) % 100 == 0:
            self._custom_print(
                f"DNS QUERY: Contacted {len(self.unique_domains)}"
                "unique domains"
            )

    def tr_contacts_many_domains(self, domains):
        self.update_trigger(
            "Contacts many domains",
            "Connects to %s..." % ",".join(domains),
            grouping="Network Activity",
        )

    def tr_contacts_malicious_domain(self, domain_name, method_name):
        self.trigger(
            "Contacts known malicious domain",
            "Connects to %s using %s" % (domain_name, method_name),
            grouping="Network Activity",
            tags=["malicious"],
        )

    # Anything that creates another process
    # readprocessmem
    # writeprocessmem
    # CreateFileMapping (mapping in a remote process)

    def tr_create_process(self, name_of_remote_process, address):
        self.trigger(
            "Creates new process",
            "Executes %s" % name_of_remote_process,
            grouping="Process Manipulation",
            tags=["evasive"],
        )
        self._custom_print(f"Process Created: {name_of_remote_process}")

    def tr_create_thread(self, thread_address, thread_name):
        msg = f'Thread "{thread_name}" address is 0x{thread_address:x}'
        self.trigger(
            "Creates new thread", msg, grouping="Process Manipulation", tags=[]
        )
        self._custom_print(f"Thread Created: {msg}")

    def tr_gets_processes(self, details):
        self.trigger(
            "Gets list of processes", details, grouping="Process Manipulation"
        )

    def tr_process_injection(self, details):
        self.trigger(
            "Injects into another process",
            details,
            grouping="Process Manipulation",
        )

    def tr_process_write(
        self, base_address, data_len, process_name, dll_region_name=None
    ):
        # Check if this writes into a known dll
        if dll_region_name is not None:
            self.trigger(
                "Writes into separate process",
                "Inserted into dll region: %s" % dll_region_name,
                grouping="Process Manipulation",
            )
        else:
            self.trigger(
                "Writes into separate process", grouping="Process Manipulation"
            )
        msg = f"Process Name: {process_name} Address: 0x{base_address:x} "
        "Bytes Written: 0x{data_len:x}"
        self._custom_print(self.process_write_message + msg)

    def tr_registry_key_open(self, key_name, sub_key_name, perm):
        self.trigger(
            "Registry Key opened",
            "Key: %s" % sub_key_name,
            grouping="Registry Key Manipulation",
        )

    def tr_registry_key_read(self, key_name, perm):
        self.trigger(
            "Registry Key read",
            "Key: %s" % key_name,
            grouping="Registry Key Manipulation",
        )

    def tr_registry_create_key(self, key_name):
        self.trigger(
            "New Registry key",
            f"Key: {key_name}",
            grouping="Registry Key Manipulation",
        )

    def tr_registry_key_value_write(self, key_name, value_name, value_data):
        max_data = 100
        if len(value_data) > max_data:
            value_data = value_data[:max_data]
        value_data = "".join([i if ord(i) < 128 else "." for i in value_data])
        msg = "%s\\%s: %s" % (key_name, value_name, value_data)
        self.trigger(
            "Value added to registry key",
            msg,
            grouping="Registry Key Manipulation",
        )
        self._custom_print(self.registry_key_write_message + msg)

    def tr_registry_key_value_read(self, key_name, value_name):
        self.trigger(
            "Value read from registry key",
            (key_name, value_name),
            rule_type=RuleType.TABLE,
            type_info=("Key", "Value Name"),
            grouping="Registry Key Manipulation",
        )

    # File System
    def tr_file_check(self, filename):
        self.trigger(
            "File details checked",
            "Name: %s" % filename,
            grouping="File System",
        )

    def tr_file_open(self, filename):
        self.trigger(
            "Files opened", "Name: %s" % filename, grouping="File System"
        )

    def tr_file_read(self):
        pass

    def tr_file_write(self, file_name, data):
        msg = f"File name: {file_name}, Wrote {len(data)} bytes"
        self.trigger("File written", msg, grouping="File System")
        self._custom_print(f"File written: {msg}")

    # Misc
    def tr_reached_entrypoint(self, address):
        if self.reached_entrypoint:
            return
        self.reached_entrypoint = True
        self.trigger("Reached EntryPoint", f"0x{address:x}")
        self._custom_print(f"Reached EntryPoint: 0x{address:x}")

    def tr_load_library(self, module_name):
        self.trigger("Runtime DLLs", module_name)
        self._custom_print(f"{self.load_library_message} {module_name}")

    def tr_mutex_open(self, mutex_name):
        self.trigger("Opens Mutex", 'Name: "%s"' % mutex_name)
        self._custom_print(f"Open Mutex: '{mutex_name}'")

    def tr_mutex_create(self, mutex_name):
        self.trigger("Creates Mutex", 'Name: "%s"' % mutex_name)
        self._custom_print(f"Create Mutex: '{mutex_name}'")

    def tr_call_crypto_func(self, func_name):
        self.trigger("Calls Crypto function", "%s" % func_name)

    def tr_sleep(self, time_slept_in_ms, address):
        if time_slept_in_ms > 2 * 60 * 1000:
            self.trigger(
                "Long Sleep",
                "Sleep for %.2f seconds" % time_slept_in_ms,
                tags=["evasive"],
            )
        self.total_time_slept_in_ms += time_slept_in_ms

    def tr_rdtsc(self, address):
        if self.seen_rdtsc:
            return
        self.seen_rdtsc = True
        self.trigger("Measures performance", "rdtsc called")
        self._custom_print(self.rdtsc_message)

    def tr_call_syscall(self, syscall_name):
        self.num_syscalls_called += 1

    def tr_syscall(self, thread, name, args, retval):
        if thread is None:
            thread_name = "NULLTHREAD"
            bb_count = 0
        else:
            thread_name = thread.name
            bb_count = thread.total_blocks_executed
        self.syscalls_called[thread_name].append(
            Syscall(name, args, retval, bb_count)
        )

    def tr_api(self, thread, name, args, retval, simulated):
        if thread is None:
            thread_name = "NULLTHREAD"
            bb_count = 0
        else:
            thread_name = thread.name
            bb_count = thread.total_blocks_executed

        self.apis_called[thread_name].append(
            Api(name, args, retval, bb_count, simulated)
        )

    def tr_unpacked_code_execution(self, region):
        if not self.exec_unpacked:
            self.exec_unpacked = True
            self._custom_print(self.exec_unpacked_message)
            self.trigger("Execute unpacked code")

    def tr_rpc(self, interface, server_name):
        self.trigger("Uses RPC", "NdrClientCall2 called")
        if server_name is not None:
            self._custom_print(
                f"{self.rpc_message}{interface} -> {server_name}"
            )
        else:
            self._custom_print(f"{self.rpc_message}{interface}")


class Syscall:
    """ A record of a syscall """

    def __init__(self, api_string, args, ret_val, bb_count):
        self.args = args
        self.ret_val = ret_val
        self.bb_count = bb_count
        self.name = api_string


class Api:
    """ A record of an api call."""

    def __init__(self, api_string, args, ret_val, bb_count, is_simulated):
        self.is_simulated = is_simulated
        self.args = args
        self.ret_val = ret_val
        self.bb_count = bb_count
        if "!" not in api_string:
            self.module = "UnknownModule"
            self.name = api_string
        else:
            self.module, self.name = api_string.split("!")

    def arg_html_string(self):
        if self.args is None:
            return "Unknown"
        arg_strings = self.args.arg_str_list()
        return "<br>".join(arg_strings)
