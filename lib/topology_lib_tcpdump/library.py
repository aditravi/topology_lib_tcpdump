# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
topology_lib_tcpdump communication library implementation.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from re import match
from re import search
from datetime import datetime
from time import sleep

# Add your library functions here.

def tcpdump_rate(sw):
    rate = 0
    total_packets = 0
    total_lines = sw('cat /tmp/interface.cap | wc -l', 'bash')
    for i in range(1, int(total_lines)):
        sw_cat = 'tail -' + str(i) + ' /tmp/interface.cap | head -1'
        packet_info = sw(sw_cat, 'bash')
        if "packets captured" in packet_info:
            total_packets = packet_info.split()[0]
        time = match(r"^\d\d?:\d\d?:\d\d?\.\d+", packet_info)
        if time:
            fields = packet_info.split()
            timestamp = datetime.strptime(fields[0],
                                          '%H:%M:%S.%f').time()
            break
    msec = (timestamp.hour * 60 * 60 + timestamp.minute * 60 +
            timestamp.second) * 1000 + (timestamp.microsecond / 1000)
    rate = int(total_packets) * 1000 / msec
    return rate


def tcpdump_capture_interface(sw, options, interface_id, wait_time, check_cpu):
    cmd_output = sw('ip netns exec swns tcpdump -D'.format(**locals()),
                    'bash')
    interface_re = (r'(?P<linux_interface>\d)\.' + str(interface_id) +
                    r'\s[\[Up, Running\]]')
    re_result = search(interface_re, cmd_output)
    assert re_result
    result = re_result.groupdict()

    sw('ip netns exec swns tcpdump -ni ' + result['linux_interface'] +
        options + ' -ttttt '
        '> /tmp/interface.cap 2>&1 &'.format(**locals()),
        'bash')
    sleep(wait_time)
    cpu_util = 0
    if check_cpu:
        top_output = sw('top -bn4 | grep "Cpu(s)" |'
                        ' sed "s/.*: *\\([0-9.]*\)%* us.*/\\1/"'
                        .format(**locals()),
                        'bash')
        cpu_samples = top_output.split('\n')
        if "top" in cpu_samples[0]:
            del cpu_samples[0]
        del cpu_samples[0]    
        for cpu_us in cpu_samples:
            cpu_util = cpu_util + float(cpu_us)
        cpu_util = str(cpu_util/3)
        print("Average CPU utilization: ")
        print(cpu_util)
    
    sw('killall tcpdump &'.format(**locals()),
        'bash')
    dict = {'cpu_util': cpu_util}
    return dict

__all__ = [
    'tcpdump_capture_interface',
    'tcpdump_rate'
]
