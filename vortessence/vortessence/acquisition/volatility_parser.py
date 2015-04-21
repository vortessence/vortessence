# Vortessence  Memory Forensics
# Copyright 2015 Bern University of Applied Sciences
#
# Author Beni Urech, beni@vortessence.org
#
# This program is  free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import os
import logging

import MySQLdb

from vortessence import utils
from vortessence.models import *


logger = logging.getLogger("vortessence")


def pslist_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            # TODO: Add Wow64 flag and session ID
            process = Process(snapshot=utils.item_store.snapshot, pid=line[2], command_line="", handles=line[5],
                              threads=line[4], ppid=line[3], offset=line[0], name=line[1], path="",
                              creation_time=line[8], exit_time=line[9] if line[9] else None)
            process.save()
            utils.item_store.processes[line[2]] = process


def dlllist_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            process = utils.get_process_by_pid(line[0])
            dll = Dll(base=abs(line[1]), size=abs(line[2]), path=line[4].rstrip(), load_count=line[3],
                      process=process)
            dll.save()
            utils.item_store.dlls.append(dll)
            if dll.path.split("\\")[-1].lower().startswith(process.name.lower()):
                process.path = dll.path
                process.save()


def cmdline_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            process = utils.get_process_by_pid(line[1])
            if process:
                process.command_line = line[2]
                process.save()


def apihooks_parser(json_file, options):
    with open(json_file) as input_file:
        data = json.load(input_file)
        memory_dump = options["memory_dump"]
        snapshot = options["snapshot"]
        for i in data["Hooks"]:
            try:
                process = Process.objects.get(snapshot=snapshot, pid=i["UniqueProcessId"])
                dll = Dll.objects.get(process=process, base=i["DllBase"])
                apihook = Apihook(hook_mode=i["Mode"], hook_type=i["Type"], process=process, dll=dll,
                                  function=i["Detail"],
                                  hook_address=i["HookAddress"], hooking_module=i["HookModule"])
            except Process.DoesNotExist, Dll.DoesNotExist:
                apihook = Apihook(hook_mode=i["Mode"], hook_type=i["Type"], function=i["Detail"],
                                  hook_address=i["HookAddress"], hooking_module=i["HookModule"])

            for j in i["Disassembly"]:
                apihook.disassembly += "Disassembly({})\n".format(j["Hop"])
                for d in j["Disassembly"]:
                    apihook.disassembly += memory_dump.format_value(d["Address"], '[addrpad]',
                                                                    snapshot.profile.name) + "\t" + d[
                                               "Bytes"] + "\t" + d["Instruction"] + "\n"
                apihook.disassembly += "\n\n"
            apihook.save()


def netscan_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            local_port = int(line[2].split(":")[-1])
            remote_address = ":".join(line[3].split(":")[:-1])
            remote_port = int(line[3].split(":")[-1]) if line[3].split(":")[-1] != "*" else 0

            connection = Connection()
            connection.snapshot = utils.item_store.snapshot
            connection.offset = line[0]
            connection.source_port = local_port if local_port != "*" else 0
            connection.destination_port = remote_port if remote_port != "*" else 0
            connection.destination_ip = remote_address
            connection.time_created = line[5]
            connection.state = line[4]
            connection.protocol = line[1]
            process = utils.get_process_by_pid(line[5])
            if line[5] > 0 and process:
                connection.process = process
            connection.save()


def svcscan_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data['rows']:
            process = utils.get_process_by_pid(line[3])
            Service(
                offset=line[0],
                process=process,
                order=line[1],
                start=line[2],
                service_name=line[4],
                display_name=line[5],
                service_type=line[6],
                service_state=line[7],
                binary_path=line[8],
                service_dll=line[9],
                snapshot=utils.item_store.snapshot).save()


def idt_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            Idt(snapshot=utils.item_store.snapshot, selector=line[2], value=line[3],
                module=line[4], section=line[5]).save()


def gdt_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            Gdt(snapshot=utils.item_store.snapshot, sel=line[1], base=line[2], limit=line[3],
                type=line[4], gr=line[6], pr=line[7], dpl=line[5]).save()


def callbacks_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            cb = 0 if line[1] == -1 else line[1]
            Callback(snapshot=utils.item_store.snapshot, type=line[0], callback=cb, module=line[2],
                     details=line[3]).save()


def driverirp_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for i in data:
            d = Driver(snapshot=utils.item_store.snapshot, name=data[i]["DriverName"], start=data[i]["DriverStart"],
                       size=data[i]["DriverSize"], start_io=data[i]["DriverStartIo"])
            d.save()
            for f in data[i]["IrpFunctions"]:
                IrpCall(driver=d, start=f["FunctionAddress"], name=f["FunctionName"], content=f["Disassembly"],
                        base_dll_name=f["BaseDllName"]).save()

            for dev in data[i]["Devices"]:
                device = Device(driver=d, offset=dev["Offset"],
                                name=dev["DeviceName"],
                                type=dev["DeviceCodes"], level=-1)
                device.save()
                for ad in dev["AttachedDevices"]:
                    Device(driver=d, offset=ad["Offset"],
                           name=ad["DeviceName"],
                           type=ad["DeviceCodes"],
                           level=ad["Level"],
                           parent_device=device).save()


def timers_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            Timer(offset=line[0], due_time=line[1], period=line[2], signaled=line[3], routine=line[4], module=line[5],
                  snapshot=utils.item_store.snapshot).save()


def unloadedmodules_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            UnloadedModules(name=line[0], start_address=line[1], end_address=line[2],
                            time=line[3], snapshot=utils.item_store.snapshot).save()


def getsids_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            process = utils.get_process_by_pid(line[0])
            Sid(process=process, process_name=line[1], sid=line[2], name=line[3]).save()


def handles_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            process = utils.get_process_by_pid(line[1])
            # TODO: remove offset type attribute
            Handle(process=process, offset_type="virtual", handle_value=line[2], offset=line[0],
                   handle_type=line[4], granted_access=line[3], handle_name=line[5]).save()


def filescan_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            Filescan(offset=line[0], pointers=line[1], handles=line[2],
                     access=line[3], name=line[4], snapshot=utils.item_store.snapshot).save()


def modscan_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            Modscan(offset=line[0], name=line[1], base=line[2],
                    size=line[3], file=line[4], snapshot=utils.item_store.snapshot).save()


def ssdt_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            # TODO: add attributes destination and hookname
            Ssdt(table=line[1], index="".join(line[0][5:-1]), offset=line[4],
                 function_name=line[5], owner=line[6],
                 snapshot=utils.item_store.snapshot, entry=line[3]).save()


def registryautostart(registry_file):
    with file(registry_file) as f:
        lines = f.readlines()
        registry_key = None

        for i in range(len(lines)):
            line = lines[i]

            if line.startswith("--------"):
                if registry_key is not None:
                    registry_key.save()

                registry_key = Registry()
                registry_key.key = "_".join(registry_file.split(os.sep)[-1].split("_")[3:]).replace("-backslash-",
                                                                                                    "\\").replace(
                    "-asterisk-", "*").replace("-slash-", "/")
                registry_key.snapshot = utils.item_store.snapshot
                registry_key.autostart = True

            if line.startswith('Registry:'):
                registry_key.hive = ":".join(line.split(":")[1:]).strip()
            if line.startswith("Last updated:"):
                registry_key.last_updated = ":".join(line.split(":")[1:]).strip()
            if line.startswith("Subkeys:"):
                i += 1
                while lines[i].startswith('  ('):
                    registry_key.subkeys += lines[i]
                    i += 1

            if line.startswith("Values:"):
                i += 1
                try:
                    while lines[i].startswith("REG_"):
                        registry_key.values += lines[i]
                        i += 1
                except IndexError:
                    pass

            i += 1

        if registry_key is not None:
            registry_key.save()


def threads_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for i in data:
            process = utils.get_process_by_pid(data[i]["UniqueProcess"])
            thread = Thread(process=process,
                            ethread=data[i]["offset"],
                            tid=data[i]["UniqueThread"],
                            snapshot=utils.item_store.snapshot,
                            created=data[i]["CreateTime"],
                            exited=data[i]["ExitTime"],
                            owning_process=data[i]["ImageFileName"],
                            attached_process=data[i]["Attached"],
                            state=data[i]["State"],
                            priority=data[i]["Priority"],
                            base_priority=data[i]["BasePriority"],
                            teb=data[i]["Teb"],
                            start_address=data[i]["StartAddress"],
                            service_table=data[i][
                                "ServiceTable"] if utils.item_store.snapshot.profile.arch == "x86" else None,
                            win32_thread=data[i]["Win32Thread"],
                            cross_thread_flags=data[i]["CrossThreadFlags"],
                            eip=""
            )

            for d in data[i]["Disassembly"]:
                thread.assembler += str(d["Address"]) + "\t" + d["Bytes"] + "\t" + d["Instruction"] + "\n"

            for t in data[i]["Tags"]:
                thread.tags += t

            thread.save()

            if process and process.priority == 0:
                process.priority = thread.base_priority
                process.save()


def vadinfo_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for i in data:
            process = utils.get_process_by_pid(data[i]["UniqueProcessId"])
            for v in data[i]["VADs"]:
                try:
                    Vad(process=process, start=v["VadShort"]["Start"], end=v["VadShort"]["End"],
                        vad_type=", ".join(v["VadShort"]["VadType"]), protection=v["VadShort"]["Protection"],
                        fileobject=v["VadControl"]["FileObject"]["FileName"] if v["VadControl"] and v["VadControl"][
                            "FileObject"] else "").save()
                except MySQLdb.Warning as details:
                    logger.error(
                        "Parsing error: unable to read VAD line for process {} with start {} and end {}. Message: {}".format(
                            process.id, v["VadShort"]["Start"], v["VadShort"]["End"], details),
                        {"snapshot": utils.item_store.snapshot})


def verinfo_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for line in data["rows"]:
            process = utils.get_process_by_pid(line[0])
            Verinfo(process=process,
                    dll=utils.get_dll_by_process_and_path(process, line[1]),
                    snapshot=utils.item_store.snapshot,
                    module=line[1],
                    file_version=line[2],
                    product_version=line[3],
                    flags=line[4],
                    os=line[5],
                    file_type=line[6],
                    file_date=line[7],
                    info_string=line[8]).save()


def malfind_parser(json_file, memory_dump):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for i in data:
            process = utils.get_process_by_pid(data[i]["UniqueProcessId"])

            malfind = Malfind(process=process, vad=data[i]["Tag"], flags=data[i]["VadFlags"],
                              protection=data[i]["Protection"],
                              start_address=data[i]["Start"], end_address=data[i]["End"])
            for d in data[i]["Disassembly"]:
                malfind.disasm_output += memory_dump.format_value(d["Address"], '[addrpad]',
                                                                  utils.item_store.snapshot.profile.name) + "\t" + d[
                                             "Bytes"] + "\t" + d["Instruction"] + "\n"

            for h in data[i]["HexDump"]:
                malfind.hex_output += memory_dump.format_value(h["Address"], '[addrpad]',
                                                               utils.item_store.snapshot.profile.name) + "\t"
                for b in h["Bytes"]:
                    malfind.hex_output += b + " "
                malfind.hex_output += "\t" + h["Chars"] + "\n"
            malfind.save()


def ldrmodules_parser(json_file):
    with open(json_file) as input_file:
        data = json.load(input_file)
        for i in data:
            process = utils.get_process_by_pid(data[i]["UniqueProcessId"])
            for l in data[i]["LdrModules"]:
                dll = utils.get_dll_by_pid_and_base(process.id, l["BaseAddress"])
                Ldrmodule(process=process, dll=dll, mapped_path=l["Path"], inmem=l["Mem"]["InMem"],
                          inload=l["Load"]["InLoad"], ininit=l["Init"]["InInit"], base=l["BaseAddress"],
                          init_path=l["Init"]["FullDllName"], mem_path=l["Mem"]["FullDllName"],
                          load_path=l["Load"]["FullDllName"]).save()


def parse_json(plugin, voloutput_folder, snapshot_id, options):
    filename = voloutput_folder + os.sep + plugin + "_" + str(snapshot_id)
    try:
        if options is not None:
            globals()[plugin + "_parser"](filename, options)
        else:
            globals()[plugin + "_parser"](filename)
    except IOError:
        logger.error("Parsing Error: file {} not found".format(filename), {"snapshot": utils.item_store.snapshot})
    except ValueError as e:
        logger.warning("Parsing Warning in file {0}: {1}".format(filename, e), {"snapshot": utils.item_store.snapshot})