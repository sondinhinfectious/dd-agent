# (C) Datadog, Inc. 2010-2016
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)

'''
Redis checks
'''
# stdlib
from collections import defaultdict
import re
import time

# 3rd party
import disq

# project
# from checks import AgentCheck
AgentCheck = object

DEFAULT_MAX_SLOW_ENTRIES = 128
MAX_SLOW_ENTRIES_KEY = "slowlog-max-len"

REPL_KEY = 'master_link_status'
LINK_DOWN_KEY = 'master_link_down_since_seconds'


class Disque(AgentCheck):
    db_key_pattern = re.compile(r'^db\d+')
    slave_key_pattern = re.compile(r'^slave\d+')
    subkeys = ['keys', 'expires']

    SOURCE_TYPE_NAME = 'disque'

    GAUGE_KEYS = {
        # Append-only metrics
        'aof_last_rewrite_time_sec':    'disque.aof.last_rewrite_time',
        'aof_rewrite_in_progress':      'disque.aof.rewrite',
        'aof_current_size':             'disque.aof.size',
        'aof_buffer_length':            'disque.aof.buffer_length',

        # Network
        'connected_clients':            'disque.net.clients',
        'connected_slaves':             'disque.net.slaves',
        'rejected_connections':         'disque.net.rejected',

        # clients
        'blocked_clients':              'disque.clients.blocked',
        'client_biggest_input_buf':     'disque.clients.biggest_input_buf',
        'client_longest_output_list':   'disque.clients.longest_output_list',

        # Keys
        'evicted_keys':                 'disque.keys.evicted',
        'expired_keys':                 'disque.keys.expired',

        # stats
        'latest_fork_usec':             'disque.perf.latest_fork_usec',

        # pubsub
        'pubsub_channels':              'disque.pubsub.channels',
        'pubsub_patterns':              'disque.pubsub.patterns',

        # rdb
        'rdb_bgsave_in_progress':       'disque.rdb.bgsave',
        'rdb_changes_since_last_save':  'disque.rdb.changes_since_last',
        'rdb_last_bgsave_time_sec':     'disque.rdb.last_bgsave_time',

        # memory
        'mem_fragmentation_ratio':      'disque.mem.fragmentation_ratio',
        'used_memory':                  'disque.mem.used',
        'used_memory_lua':              'disque.mem.lua',
        'used_memory_peak':             'disque.mem.peak',
        'used_memory_rss':              'disque.mem.rss',

        # replication
        'master_last_io_seconds_ago':   'disque.replication.last_io_seconds_ago',
        'master_sync_in_progress':      'disque.replication.sync',
        'master_sync_left_bytes':       'disque.replication.sync_left_bytes',
        'repl_backlog_histlen':         'disque.replication.backlog_histlen',
        'master_repl_offset':           'disque.replication.master_repl_offset',
        'slave_repl_offset':            'disque.replication.slave_repl_offset',
    }

    RATE_KEYS = {
        # cpu
        'used_cpu_sys':                 'disque.cpu.sys',
        'used_cpu_sys_children':        'disque.cpu.sys_children',
        'used_cpu_user':                'disque.cpu.user',
        'used_cpu_user_children':       'disque.cpu.user_children',

        # stats
        'keyspace_hits':                'disque.stats.keyspace_hits',
        'keyspace_misses':              'disque.stats.keyspace_misses',
    }

    def __init__(self, name, init_config, agentConfig, instances=None):
        AgentCheck.__init__(self, name, init_config, agentConfig, instances)
        self.connections = {}
        self.last_timestamp_seen = defaultdict(int)

    def get_library_versions(self):
        return {"disque": disq.__version__}

    def _generate_instance_key(self, instance):
        if 'unix_socket_path' in instance:
            return (instance.get('unix_socket_path'), instance.get('db'))
        else:
            return (instance.get('host'), instance.get('port'), instance.get('db'))

    def _get_conn(self, instance):
        key = self._generate_instance_key(instance)
        if key not in self.connections:
            try:

                # Only send useful parameters to the disque client constructor
                list_params = ['host', 'port', 'password', 'socket_timeout',
                               'connection_pool', 'unix_socket_path']

                # Set a default timeout (in seconds) if no timeout is specified in the instance config
                instance['socket_timeout'] = instance.get('socket_timeout', 5)

                connection_params = dict((k, instance[k]) for k in list_params if k in instance)

                self.connections[key] = disq.Disque(**connection_params)

            except TypeError:
                raise Exception("You need a disque library that supports authenticated connections. Try sudo easy_install disq.")

        return self.connections[key]

    def _get_tags(self, custom_tags, instance):
        tags = set(custom_tags or [])

        if 'unix_socket_path' in instance:
            tags_to_add = [
                "disque_host:%s" % instance.get("unix_socket_path"),
                "disque_port:unix_socket",
            ]
        else:
            tags_to_add = [
                "disque_host:%s" % instance.get('host'),
                "disque_port:%s" % instance.get('port')
            ]

        tags = sorted(tags.union(tags_to_add))

        return tags, tags_to_add

    def _check_db(self, instance, custom_tags=None):
        conn = self._get_conn(instance)

        tags, tags_to_add = self._get_tags(custom_tags, instance)

        # Ping the database for info, and track the latency.
        # Process the service check: the check passes if we can connect to Redis
        start = time.time()
        info = None
        try:
            info = conn.info()
            status = AgentCheck.OK
            self.service_check('disque.can_connect', status, tags=tags_to_add)
            self._collect_metadata(info)
        except ValueError:
            status = AgentCheck.CRITICAL
            self.service_check('disque.can_connect', status, tags=tags_to_add)
            raise
        except Exception:
            status = AgentCheck.CRITICAL
            self.service_check('disque.can_connect', status, tags=tags_to_add)
            raise

        latency_ms = round((time.time() - start) * 1000, 2)
        self.gauge('disque.info.latency_ms', latency_ms, tags=tags)

        # Save the database statistics.
        for key in info.keys():
            if self.db_key_pattern.match(key):
                db_tags = list(tags) + ["disque_db:" + key]
                # allows tracking percentage of expired keys as DD does not
                # currently allow arithmetic on metric for monitoring
                expires_keys = info[key]["expires"]
                total_keys = info[key]["keys"]
                persist_keys = total_keys - expires_keys
                self.gauge("disque.persist", persist_keys, tags=db_tags)
                self.gauge("disque.persist.percent", 100.0 * persist_keys / total_keys, tags=db_tags)
                self.gauge("disque.expires.percent", 100.0 * expires_keys / total_keys, tags=db_tags)

                for subkey in self.subkeys:
                    val = info[key].get(subkey, -1)
                    metric = '.'.join(['disque', subkey])
                    self.gauge(metric, val, tags=db_tags)

        # Save a subset of db-wide statistics
        for info_name, value in info.iteritems():
            if info_name in self.GAUGE_KEYS:
                self.gauge(self.GAUGE_KEYS[info_name], info[info_name], tags=tags)
            elif info_name in self.RATE_KEYS:
                self.rate(self.RATE_KEYS[info_name], info[info_name], tags=tags)

        # Save the number of commands.
        self.rate('disque.net.commands', info['total_commands_processed'],
                  tags=tags)

        self._check_replication(info, tags)
        if instance.get("command_stats", False):
            self._check_command_stats(conn, tags)

    def _check_replication(self, info, tags):

        # Save the replication delay for each slave
        for key in info:
            if self.slave_key_pattern.match(key) and isinstance(info[key], dict):
                slave_offset = info[key].get('offset')
                master_offset = info.get('master_repl_offset')
                if slave_offset and master_offset and master_offset - slave_offset >= 0:
                    delay = master_offset - slave_offset
                    # Add id, ip, and port tags for the slave
                    slave_tags = tags[:]
                    for slave_tag in ('ip', 'port'):
                        if slave_tag in info[key]:
                            slave_tags.append('slave_{0}:{1}'.format(slave_tag, info[key][slave_tag]))
                    slave_tags.append('slave_id:%s' % key.lstrip('slave'))
                    self.gauge('disque.replication.delay', delay, tags=slave_tags)

        if REPL_KEY in info:
            if info[REPL_KEY] == 'up':
                status = AgentCheck.OK
                down_seconds = 0
            else:
                status = AgentCheck.CRITICAL
                down_seconds = info[LINK_DOWN_KEY]

            self.service_check('disque.replication.master_link_status', status, tags=tags)
            self.gauge('disque.replication.master_link_down_since_seconds', down_seconds, tags=tags)

    def _check_slowlog(self, instance, custom_tags):
        """Retrieve length and entries from Disque's SLOWLOG

        This will parse through all entries of the SLOWLOG and select ones
        within the time range between the last seen entries and now

        """
        conn = self._get_conn(instance)

        tags, _ = self._get_tags(custom_tags, instance)

        if not instance.get(MAX_SLOW_ENTRIES_KEY):
            try:
                max_slow_entries = int(conn.config_get(MAX_SLOW_ENTRIES_KEY)[MAX_SLOW_ENTRIES_KEY])
                if max_slow_entries > DEFAULT_MAX_SLOW_ENTRIES:
                    self.warning("Disque {0} is higher than {1}. Defaulting to {1}."
                                 "If you need a higher value, please set {0} in your check config"
                                 .format(MAX_SLOW_ENTRIES_KEY, DEFAULT_MAX_SLOW_ENTRIES))
                    max_slow_entries = DEFAULT_MAX_SLOW_ENTRIES
            # No config on AWS Elasticache
            except disq.ResponseError:
                max_slow_entries = DEFAULT_MAX_SLOW_ENTRIES
        else:
            max_slow_entries = int(instance.get(MAX_SLOW_ENTRIES_KEY))

        # Generate a unique id for this instance to be persisted across runs
        ts_key = self._generate_instance_key(instance)

        # Get all slowlog entries

        slowlogs = conn.slowlog_get(max_slow_entries)

        # Find slowlog entries between last timestamp and now using start_time
        slowlogs = [s for s in slowlogs if s['start_time'] >
            self.last_timestamp_seen[ts_key]]

        max_ts = 0
        # Slowlog entry looks like:
        #  {'command': 'LPOP somekey',
        #   'duration': 11238,
        #   'id': 496L,
        #   'start_time': 1422529869}
        for slowlog in slowlogs:
            if slowlog['start_time'] > max_ts:
                max_ts = slowlog['start_time']

            command_tag = 'command:{0}'.format(slowlog['command'].split()[0])
            value = slowlog['duration']
            self.histogram('disque.slowlog.micros', value, tags=tags + [command_tag])

        self.last_timestamp_seen[ts_key] = max_ts

    def _check_command_stats(self, conn, tags):
        """Get command-specific statistics from redis' INFO COMMANDSTATS command
        """
        try:
            command_stats = conn.info("commandstats")
        except Exception:
            self.warning("Could not retrieve command stats from Disque.")
            return

        for key, stats in command_stats.iteritems():
            command = key.split('_', 1)[1]
            command_tags = tags + ['command:%s' % command]
            self.gauge('disque.command.calls', stats['calls'], tags=command_tags)
            self.gauge('disque.command.usec_per_call', stats['usec_per_call'], tags=command_tags)

    def check(self, instance):
        if ("host" not in instance or "port" not in instance) and "unix_socket_path" not in instance:
            raise Exception("You must specify a host/port couple or a unix_socket_path")
        custom_tags = instance.get('tags', [])

        self._check_db(instance, custom_tags)
        self._check_slowlog(instance, custom_tags)

    def _collect_metadata(self, info):
        if info and 'disque_version' in info:
            self.service_metadata('version', info['disque_version'])
