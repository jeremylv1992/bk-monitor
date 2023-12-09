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

import json
from typing import Dict, List

from django.conf import settings

from bkmonitor.models import StrategyLabel
from bkmonitor.utils.common_utils import logger
from core.drf_resource import resource
from monitor_web.models.collecting import CollectConfigMeta
from monitor_web.models.plugin import PluginVersionHistory
from monitor_web.plugin.constant import PluginType
from monitor_web.strategies.default_settings.datalink.v1 import (
    DEFAULT_DATALINK_STRATEGIES,
    DataLinkStage,
    DatalinkStategy,
)
from monitor_web.strategies.user_groups import add_member_to_collecting_notice_group

__all__ = ["DatalinkDefaultAlarmStrategyLoader"]


class DatalinkDefaultAlarmStrategyLoader:
    """创建采集配置时，自动创建默认告警策略"""

    def __init__(self, collect_config: CollectConfigMeta, user_id: str):
        self.user_id = user_id
        self.collect_config = collect_config
        self.bk_biz_id = self.collect_config.bk_biz_id
        self.collect_config_id = self.collect_config.id
        self.collect_config_name = self.collect_config.name

    def get_result_table_id(self):
        """计算结果表ID，目前仅支持单指标单表，并且指标为 bkm_gather_up 的告警策略"""
        if self.collect_config.plugin.plugin_type == PluginType.PROCESS:
            return "process.perf"
        return PluginVersionHistory.get_result_table_id(self.collect_config.plugin, "__default__")

    def check_strategy_exist(self, name: DatalinkStategy) -> bool:
        """检测策略是否存在"""
        label = self.render_label(name)
        return bool(StrategyLabel.objects.filter(bk_biz_id=self.bk_biz_id, label_name="/{}/".format(label)).exists())

    def render_label(self, name: DatalinkStategy) -> str:
        """根据默认告警策略，生成唯一标签"""
        return name.render_label(collect_config_id=self.collect_config_id, bk_biz_id=self.bk_biz_id)

    def get_default_strategy(self):
        """获得默认告警策略 ."""
        return DEFAULT_DATALINK_STRATEGIES

    def init_notice_group(self) -> int:
        """获得告警通知组 ."""
        return add_member_to_collecting_notice_group(self.bk_biz_id, self.user_id)

    def run(self) -> None:
        if self.collect_config.plugin.plugin_type not in [
            PluginType.SCRIPT,
            PluginType.PROCESS,
            PluginType.PUSHGATEWAY,
            PluginType.EXPORTER,
            PluginType.DATADOG,
        ]:
            logger.info("Plugin ({}) has no initial strategy".format(self.collect_config.plugin.plugin_type))
            return

        # 获得默认告警策略
        strategies_list = self.get_default_strategy()
        if not strategies_list:
            return

        # 添加默认告警策略
        for item in strategies_list:
            if self.check_strategy_exist(item["_name"]):
                logger.info("Strategy({}, {}) has exist ...".format(self.collect_config_id, item["_name"]))
                continue
            try:
                self.load_strategy(item)
            except Exception as err:
                logger.exception(
                    "Fail to load/initial strategy({}) in CollectConfig({}:{}), {}".format(
                        item["_name"], self.collect_config_id, self.collect_config_name, err
                    )
                )

    def load_strategy(self, strategy: Dict):
        """加载k8s默认告警策略 ."""
        _name: DatalinkStategy = strategy.pop("_name")
        # 占位符渲染
        strategy_str = json.dumps(strategy)
        strategy_str = strategy_str.replace("${{result_table_id}}", self.get_result_table_id())
        strategy_str = strategy_str.replace("${{collect_config_id}}", str(self.collect_config_id))
        strategy_str = strategy_str.replace("${{collect_config_name}}", self.collect_config_name)
        strategy_str = strategy_str.replace("${{custom_label}}", self.render_label(_name))
        strategy = json.loads(strategy_str)

        # 组装通知信息
        notice_group_id = self.init_notice_group()
        notice = strategy["notice"]
        notice["user_groups"] = [notice_group_id]
        notice["config"]["template"] = settings.DEFAULT_NOTICE_MESSAGE_TEMPLATE

        # 组装最终结构
        strategy_config = {
            "bk_biz_id": self.bk_biz_id,
            "name": strategy["name"],
            "source": "bk_monitorv3",
            "scenario": "kubernetes",
            "type": "monitor",
            "labels": strategy["labels"],
            "detects": strategy["detects"],
            "items": strategy["items"],
            "notice": notice,
            "actions": [],
        }
        # 保存策略
        resource.strategies.save_strategy_v2(**strategy_config)


def get_datalink_strategy_ids(bk_biz_id: int, collect_config_id: int, stage: str) -> List[int]:
    """读取数据链路告警策略"""
    if DataLinkStage(stage) == DataLinkStage.COLLECTING:
        labels = [
            DatalinkStategy.COLLECTING_SYS_ALARM.render_escaped_label(collect_config_id=collect_config_id),
            DatalinkStategy.COLLECTING_USER_ALARM.render_escaped_label(collect_config_id=collect_config_id),
        ]
        return list(
            StrategyLabel.objects.filter(bk_biz_id=bk_biz_id, label_name__in=labels).values_list(
                "strategy_id", flat=True
            )
        )
    return []
