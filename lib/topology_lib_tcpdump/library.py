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

import datetime
import re
import time

# Add your library functions here.

def tcpdump_rate(sw):
    total_packets = sw('cat /tmp/interface.cap | wc -l', 'bash')
    total_packets = int(total_packets.strip()) - 1
    last_packet = sw('tail -2 /tmp/interface.cap | head -1', 'bash')
    fields = last_packet.split()
    print(fields)
    timestamp = datetime.datetime.strptime(fields[0], '%H:%M:%S.%f').time()
    print(timestamp)
    msec = (timestamp.hour * 60 * 60 + timestamp.minute * 60 +
            timestamp.second) * 1000 + (timestamp.microsecond / 1000)
    rate = total_packets * 1000 / msec
    return rate

def tcpdump_capture_interface(sw, options, interface_id, wait_time, check_cpu):
    cmd_output = sw('ip netns exec swns tcpdump -D'.format(**locals()),
                    'bash')
    interface_re = (r'(?P<linux_interface>\d)\.' + str(interface_id) +
                    r'\s[\[Up, Running\]]')
    re_result = re.search(interface_re, cmd_output)
    assert re_result
    result = re_result.groupdict()

    sw('ip netns exec swns tcpdump -ni ' + result['linux_interface'] +
        options + ' -ttttt '
        '> /tmp/interface.cap &'.format(**locals()),
        'bash')
    time.sleep(wait_time)
    cpu_util = 0
    if check_cpu:
        top_output = sw('top -bn3 | grep "Cpu(s)" |'
                          ' sed "s/.*, *\\([0-9.]*\)%* id.*/\\1/"'
                          .format(**locals()),
                          'bash')
        cpu_samples = top_output.split('\n')
        if "top" in cpu_samples[0]:
            del cpu_samples[0]
        for cpu_idle in cpu_samples:
            cpu_util = cpu_util + (100 - float(cpu_idle))
        cpu_util = str(cpu_util/3)
        print("Average CPU utilization: ")
        print(cpu_util)
    
    sw('killall tcpdump &'.format(**locals()),
        'bash')
    dict = {'cpu_util': cpu_util};    
    return dict

__all__ = [
    'tcpdump_capture_interface',
    'tcpdump_rate'
]
