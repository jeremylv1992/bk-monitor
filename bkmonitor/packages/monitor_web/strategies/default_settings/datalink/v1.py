# -*- coding: utf-8 -*-
"""
Tencent is pleased to support the open source community by making 蓝鲸智云 - 监控平台 (BlueKing - Monitor) available.
Copyright (C) 2017-2021 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import enum

from django.utils.translation import ugettext as _

from monitor_web.strategies.default_settings.common import (
    DEFAULT_NOTICE,
    NO_DATA_CONFIG,
    warning_algorithms_config,
    warning_detects_config,
)


class DatalinkStategy(enum.Enum):
    COLLECTING_USER_ALARM = "datalink_collecting_user_alarm"
    COLLECTING_SYS_ALARM = "datalink_collecting_sys_alarm"

    @property
    def label_pattern_mapping(self):
        return {
            DatalinkStategy.COLLECTING_SYS_ALARM: "datalink_collecting_sys_{collect_config_id}",
            DatalinkStategy.COLLECTING_USER_ALARM: "datalink_collecting_user_{collect_config_id}",
        }

    def render_label(self, **context):
        return self.label_pattern_mapping[self].format(**context)

    def render_escaped_label(self, **context):
        return "/{}/".format(self.render_label(**context))


class DataLinkStage(enum.Enum):
    COLLECTING = "collecting"
    TRANSFER = "transfer"
    STORAGE = "storage"


DEFAULT_DATALINK_STRATEGIES = [
    {
        "_name": DatalinkStategy.COLLECTING_SYS_ALARM,
        "detects": warning_detects_config(5, 5, 4),
        "items": [
            {
                "algorithms": warning_algorithms_config("gt", 0),
                "expression": "a",
                "functions": [],
                "name": "count(bkm_gather_up)",
                "no_data_config": NO_DATA_CONFIG,
                "query_configs": [
                    {
                        "agg_condition": [
                            {"key": "bkm_up_code", "method": "nreg", "value": ["^2\\d{3}$"]},
                            {"key": "bkm_up_code", "method": "neq", "value": ["0"], "condition": "and"},
                            {
                                "key": "bk_collect_config_id",
                                "method": "eq",
                                "value": ["${{collect_config_id}}"],
                                "condition": "and",
                            },
                        ],
                        "agg_dimension": ["bkm_up_code", "bk_target_ip", "bk_target_cloud_id"],
                        "agg_interval": 60,
                        "agg_method": "COUNT",
                        "alias": "a",
                        "data_source_label": "bk_monitor",
                        "data_type_label": "time_series",
                        "functions": [],
                        "metric_field": "bkm_gather_up",
                        "name": "bkm_gather_up",
                        "result_table_id": "${{result_table_id}}",
                        "unit": "",
                    },
                ],
                "target": [[]],
            }
        ],
        "labels": [_("采集内置"), "${{custom_label}}"],
        "name": _("数据采集 - ${{collect_config_name}} 系统运行异常告警"),
        "notice": DEFAULT_NOTICE,
    },
    {
        "_name": DatalinkStategy.COLLECTING_USER_ALARM,
        "detects": warning_detects_config(5, 5, 4),
        "items": [
            {
                "algorithms": warning_algorithms_config("gt", 0),
                "expression": "a",
                "functions": [],
                "name": "count(bkm_gather_up)",
                "no_data_config": NO_DATA_CONFIG,
                "query_configs": [
                    {
                        "agg_condition": [
                            {"key": "bkm_up_code", "method": "reg", "value": ["^2\\d{3}$"]},
                            {
                                "key": "bk_collect_config_id",
                                "method": "eq",
                                "value": ["${{collect_config_id}}"],
                                "condition": "and",
                            },
                        ],
                        "agg_dimension": ["bkm_up_code", "bk_target_ip", "bk_target_cloud_id"],
                        "agg_interval": 60,
                        "agg_method": "count",
                        "alias": "a",
                        "data_source_label": "bk_monitor",
                        "data_type_label": "time_series",
                        "functions": [],
                        "metric_field": "bkm_gather_up",
                        "name": "bkm_gather_up",
                        "result_table_id": "${{result_table_id}}",
                        "unit": "",
                    },
                ],
                "target": [[]],
            }
        ],
        "labels": [_("采集内置"), "${{custom_label}}"],
        "name": _("数据采集 - ${{collect_config_name}} 插件执行异常告警"),
        "notice": DEFAULT_NOTICE,
    },
]
