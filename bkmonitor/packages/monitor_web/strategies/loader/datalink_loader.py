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
from typing import Dict, List, Optional, Tuple

from django.conf import settings
from typing_extensions import TypedDict

from bkmonitor.models import StrategyLabel
from bkmonitor.utils.common_utils import logger
from core.drf_resource import resource
from monitor_web.models.collecting import CollectConfigMeta
from monitor_web.strategies.default_settings.datalink.v1 import (
    DATALINK_GATHER_STATEGY_DESC,
    DEFAULT_DATALINK_STRATEGIES,
    PLUGIN_TYPE_MAPPING,
    RULE_GROUP_NAME,
    STAGE_STRATEGY_MAPPING,
    DataLinkStage,
    DatalinkStrategy,
    GatherType,
)
from monitor_web.strategies.user_groups import add_member_to_collecting_notice_group

DataLinkStategyInfo = TypedDict("DataLinkStategyInfo", {"strategy_id": int, "strategy_desc": str})


class DatalinkDefaultAlarmStrategyLoader:
    """创建采集配置时，自动创建默认告警策略"""

    def __init__(self, collect_config: CollectConfigMeta, user_id: str):
        self.user_id = user_id
        self.collect_config = collect_config
        self.bk_biz_id = self.collect_config.bk_biz_id
        self.collect_config_id = self.collect_config.id
        self.collect_config_name = self.collect_config.name

    def check_strategy_exist(self, name: DatalinkStrategy) -> Optional[int]:
        """检测策略是否存在"""
        label = self.render_label(name)
        insts = StrategyLabel.objects.filter(bk_biz_id=self.bk_biz_id, label_name="/{}/".format(label))
        if insts.exists() == 0:
            return None
        return insts[0].strategy_id

    def render_label(self, name: DatalinkStrategy) -> str:
        """根据默认告警策略，生成唯一标签"""
        return name.render_label(collect_config_id=self.collect_config_id, bk_biz_id=self.bk_biz_id)

    def get_default_strategy(self):
        """获得默认告警策略 ."""
        return DEFAULT_DATALINK_STRATEGIES

    def init_notice_group(self) -> int:
        """获得告警通知组 ."""
        return add_member_to_collecting_notice_group(self.bk_biz_id, self.user_id)

    def run(self):
        if not self.get_gather_type():
            logger.info("Plugin ({}) has no initial strategy".format(self.collect_config.plugin.plugin_type))
            return

        # 获得默认告警策略
        strategies_list = self.get_default_strategy()
        if not strategies_list:
            return

        # 初始化默认告警组
        notice_group_id = self.init_notice_group()

        # 添加默认告警策略
        strategy_ids = []
        for item in strategies_list:
            strategy_id = self.check_strategy_exist(item["_name"])
            if strategy_id is not None:
                strategy_ids.append(strategy_id)
                logger.info("Strategy({}, {}) has exist ...".format(self.collect_config_id, item["_name"]))
                continue
            try:
                new_strategy_id = self.update_strategy(item, notice_group_id)
                strategy_ids.append(new_strategy_id)
            except Exception as err:
                logger.exception(
                    "Fail to load/initial strategy({}) in CollectConfig({}:{}), {}".format(
                        item["_name"], self.collect_config_id, self.collect_config_name, err
                    )
                )

        # 添加告警分派规则
        # try:
        #     self.update_rule_group([notice_group_id], strategy_ids)
        # except Exception as err:
        #     logger.exception("Fail to save rule groups according to strategies({})".format(strategy_ids))

    def update_strategy(self, strategy: Dict, notice_group_id: int) -> int:
        """加载默认告警策略 ."""
        _name: DatalinkStrategy = strategy.pop("_name")
        # 占位符渲染
        strategy_str = json.dumps(strategy)
        strategy_str = strategy_str.replace("${{collect_config_id}}", str(self.collect_config_id))
        strategy_str = strategy_str.replace("${{collect_config_name}}", self.collect_config_name)
        strategy_str = strategy_str.replace("${{custom_label}}", self.render_label(_name))
        strategy = json.loads(strategy_str)

        # 组装通知信息
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
        return resource.strategies.save_strategy_v2(**strategy_config)["id"]

    def update_rule_group(self, user_group_id, strategy_ids):
        """保存告警分派组"""
        has_news, rule_group = self.build_rules(strategy_ids, user_group_id)
        if has_news:
            resource.action.save_rule_group(rule_group)

    def build_rule_group(self, strategy_ids: List[int], group_ids: List[int], rule_group: Dict) -> Tuple[bool, Dict]:
        """构建告警分派组"""
        default_rule_group = {
            "name": RULE_GROUP_NAME,
            "bk_biz_id": self.bk_biz_id,
            "priority": 999,
            "settings": {},
            "rules": [],
        }
        rule_groups = resource.action.search_rule_group(bk_biz_id=self.bk_biz_id, name=RULE_GROUP_NAME)
        rule_group = rule_groups[0] if len(rule_groups) > 0 else default_rule_group

        has_news = False
        for strategy_id in strategy_ids:
            rule = {
                "bk_biz_id": self.bk_biz_id,
                "is_enabled": True,
                "user_groups": group_ids,
                "conditions": [
                    {"field": "alert.strategy_id", "value": [strategy_id], "method": "eq", "condition": "and"},
                    {
                        "field": "bk_collect_config_id",
                        "value": [self.collect_config_id],
                        "method": "eq",
                        "condition": "and",
                    },
                ],
                "additional_tags": [{"key": "idx", "value": self.build_rule_idx(strategy_id)}],
            }
            if not self.has_rule(rule_group, rule):
                has_news = True
                rule_group["rules"].append(rule)
        return has_news, rule_group

    def build_rule_idx(self, strategy_id: int):
        """构建分派规则唯一标识"""
        return "idx_{}_{}".format(strategy_id, self.collect_config_id)

    def has_rule(self, rule_group: Dict, new_rule: Dict) -> bool:
        """检查是否有匹配的分派规则"""
        new_idx = new_rule["additional_tags"][0]["value"]
        return bool(self._extract_rules(rule_group, new_idx))

    def _extract_rules(self, rule_group: Dict, target_idx: str) -> List:
        """从分派组中提取符合要求的分配规则"""
        rules = []
        for rule in rule_group["rules"]:
            if len(rule["additional_tags"]) > 0:
                idx = rule["additional_tags"][0]["value"]
                if idx == target_idx:
                    rules.append(rule)
        return rules

    def _retrieve_rule_group(self) -> Optional[Dict]:
        """读取采集相关的告警分派组"""
        rule_groups = resource.action.search_rule_group(bk_biz_id=self.bk_biz_id, name=RULE_GROUP_NAME)
        return rule_groups[0] if len(rule_groups) > 0 else None

    def load_rules(self, strategy_id) -> List[Dict]:
        """读取采集相关的分派规则"""
        rule_group = self._retrieve_rule_group()
        if rule_group is None:
            return []
        return self.retrieve_rules(rule_group, self.build_rule_idx(strategy_id=strategy_id))

    def load_strategy_map(self, stage: DataLinkStage) -> Dict[int, DataLinkStategyInfo]:
        """基于采集配置加载告警配置信息"""
        map = {}
        gather_type = self.get_gather_type()
        if gather_type is None:
            return map

        for strategy_name in STAGE_STRATEGY_MAPPING[stage]:
            try:
                strategy_label = StrategyLabel.objects.get(
                    bk_biz_id=self.bk_biz_id, label_name=strategy_name.render_escaped_label()
                )
            except StrategyLabel.DoesNotExist:
                continue
            map[strategy_label.id] = {
                "strategy_id": strategy_label.id,
                "strategy_desc": DATALINK_GATHER_STATEGY_DESC[(strategy_name, gather_type)],
            }
        return map

    def get_gather_type(self) -> GatherType:
        plugin_type = self.collect_config.plugin.plugin_type
        return PLUGIN_TYPE_MAPPING[plugin_type] if plugin_type in PLUGIN_TYPE_MAPPING else None
