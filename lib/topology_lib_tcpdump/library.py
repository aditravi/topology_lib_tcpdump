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


def tcpdump_rate(enode, interface_name):
    """
    Get packet rate in packets per second after capture has been run.

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :param str interface_name: Interface name on which capture was run.
    :rtype: int
    :return: The rate of packets catured in packets per second.
    """
    rate = 0
    total_packets = 0
    output = enode('cat /tmp/{}.cap | wc -l'.format(interface_name),
                   shell='bash')
    total_lines = output.split("\n")[0]
    for i in range(1, int(total_lines)):
        cmd = ('tail -{line_num} /tmp/{interface_name}.cap |'
               ' head -1').format(line_num=i, interface_name=interface_name)
        packet_info = enode(cmd, shell='bash')
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


def tcpdump_analyze(enode, interface_name):
    """
    Get packet rate in packets per second after capture has been run.
    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :param str interface_name: Interface name on which capture was run.
    :rtype: int
    :return: The rate of packets catured in packets per second.
    """
    rate = 0
    total_packets = 0
    output = enode('cat /tmp/{}.cap | wc -l'.format(interface_name),
                   shell='bash')
    total_lines = output.split("\n")[0]
    for i in range(1, int(total_lines)):
        cmd = ('tail -{line_num} /tmp/{interface_name}.cap |'
               ' head -1').format(line_num=i, interface_name=interface_name)
        packet_info = enode(cmd, shell='bash')
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
    return {'rate': cpu_util, 'msec': msec}


def tcpdump_capture_interface(enode, interface_name, capture_time,
                              options='', num_cpu_samples=0, namespace=None):
    """
    Start packet capture using tcpdump.

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :param str options: The filter options to be passed to tcpdump.
    :param str interface_name: interface name.
    :param int capture_time: Time in seconds to capture with tcpdump.
    :param int num_cpu_samples: Number of CPU samples to get CPU utilization.
    :param str namespace: The network namespace in which to run the capture.
    :rtype: dict
    :return: Dictionary of any metadata with information collected
     during the capture.
    """
    cmd = [
        'tcpdump -D',
    ]

    if namespace:
        cmd.insert(0, 'ip netns exec {} '.format(namespace))

    cmd_output = enode(' '.join(cmd), shell='bash')
    if namespace:
        interface_re = (r'(?P<linux_interface>\d)\.' + 
                        str(interface_name) +
                        r'\s[\[Up, Running\]]')
    else:
        interface_re = (r'(?P<linux_interface>\d)\.' +
                        str(interface_name))
    re_result = search(interface_re, cmd_output)
    assert re_result
    result = re_result.groupdict()

    cmd = [
        'tcpdump -ni ',
        result['linux_interface'],
        ' ',
        options,
        ' -ttttt > /tmp/',
        interface_name,
        '.cap 2>&1 &'
    ]
    if namespace:
        cmd.insert(0, 'ip netns exec {} '.format(namespace))

    enode(''.join(cmd), shell='bash')

    sleep(capture_time)
    cpu_util = 0.0
    if num_cpu_samples:
        cmd = ('top -bn{num_samples}'
               '| grep "Cpu(s)" | sed "s/.*: *\\([0-9.]*\)%* '
               'us.*/\\1/"').format(num_samples=(num_cpu_samples + 1))
        top_output = enode(cmd, shell='bash')
        cpu_samples = top_output.split('\n')
        if 'top' in cpu_samples[0]:
            del cpu_samples[0]
        del cpu_samples[0]
        for cpu_us in cpu_samples:
            if 'tcpdump' not in cpu_us:
                cpu_util = cpu_util + float(cpu_us)
        cpu_util = cpu_util/num_cpu_samples

    enode('killall tcpdump &', shell='bash')
    return {'cpu_util': cpu_util}

__all__ = [
    'tcpdump_capture_interface',
    'tcpdump_rate',
    'tcpdump_analyze'
]
